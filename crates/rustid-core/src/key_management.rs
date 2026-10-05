//! Automatic key management. Keys are created on
//! first use, announced for `propagation_time` before they sign, used for
//! `rotation_interval`, kept for validation for `retention_duration`, then
//! deleted. Work happens lazily when keys are requested.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::data_protection::DataProtector;
use crate::keys::{KeyOrigin, LoadedKey, generate_pkcs8, self_signed_certificate};
use crate::options::{KeyManagementOptions, SigningAlgorithmOptions};
use crate::stores::{SerializedKey, SigningKeyStore, StoreError};

/// Data protection purpose for stored signing keys.
pub const KEY_PROTECTION_PURPOSE: &str = "rustid.signing-keys.v1";

/// `SerializedKey.Version` for keys this server writes.
const KEY_VERSION: i32 = 1;

/// How long to wait for another task creating keys.
const NEW_KEY_LOCK_TIMEOUT: Duration = Duration::from_secs(60);

/// The time source, replaceable in tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyManagerError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("timed out waiting for the new key lock")]
    LockTimeout,
    #[error("creating a {alg} key failed: {message}")]
    Create { alg: String, message: String },
    #[error("Failed to create and then load new keys.")]
    NoKeys,
}

/// A usable key with its management metadata: `KeyContainer`.
#[derive(Debug, Clone)]
pub struct KeyContainer {
    pub id: String,
    pub algorithm: String,
    pub created: DateTime<Utc>,
    pub key: Arc<LoadedKey>,
}

impl KeyContainer {
    pub fn has_x509_certificate(&self) -> bool {
        self.key.has_certificate()
    }
}

/// A key as the key manager stores it: PKCS#8 and the optional certificate
/// (DER) in `data`, protected under the key ring when `protector` is given.
/// What the manager does with the keys it makes, and what `rustid-server
/// import` does with migrated ones.
pub fn seal_key(
    id: &str,
    algorithm: &str,
    created: DateTime<Utc>,
    pkcs8: &[u8],
    certificate: Option<&[u8]>,
    protector: Option<&DataProtector>,
) -> Result<SerializedKey, String> {
    let data = serde_json::to_string(&KeyData {
        pkcs8: STANDARD.encode(pkcs8),
        certificate: certificate.map(|c| STANDARD.encode(c)),
    })
    .map_err(|e| e.to_string())?;
    let (data, data_protected) = match protector {
        Some(protector) => (
            protector.protect(KEY_PROTECTION_PURPOSE, data.as_bytes()),
            true,
        ),
        None => (data, false),
    };
    Ok(SerializedKey {
        version: KEY_VERSION,
        id: id.to_owned(),
        created,
        algorithm: algorithm.to_owned(),
        is_x509_certificate: certificate.is_some(),
        data,
        data_protected,
    })
}

/// What `data` holds once unprotected.
#[derive(Serialize, Deserialize)]
struct KeyData {
    pkcs8: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedKeys {
    keys: Vec<KeyContainer>,
    expires: DateTime<Utc>,
}

pub struct KeyManager {
    options: KeyManagementOptions,
    store: Arc<dyn SigningKeyStore>,
    protector: Option<Arc<DataProtector>>,
    clock: Arc<dyn Clock>,
    /// Subject of self-signed certificates (`CN=`), the issuer.
    certificate_subject: String,
    cache: Mutex<Option<CachedKeys>>,
    new_key_lock: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for KeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyManager")
            .field("options", &self.options)
            .finish_non_exhaustive()
    }
}

fn seconds(n: i64) -> chrono::Duration {
    chrono::Duration::try_seconds(n).unwrap_or(chrono::Duration::MAX)
}

impl KeyManager {
    /// `options` must already be `validated()`. `protector` is required when
    /// `data_protect_keys` is set.
    pub fn new(
        options: KeyManagementOptions,
        store: Arc<dyn SigningKeyStore>,
        protector: Option<Arc<DataProtector>>,
        clock: Arc<dyn Clock>,
        certificate_subject: &str,
    ) -> Self {
        KeyManager {
            options,
            store,
            protector,
            clock,
            certificate_subject: certificate_subject.to_owned(),
            cache: Mutex::new(None),
            new_key_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn options(&self) -> &KeyManagementOptions {
        &self.options
    }

    /// The key signing for each algorithm now.
    #[tracing::instrument(name = "keys.current", skip_all)]
    pub async fn get_current_keys(&self) -> Result<Vec<KeyContainer>, KeyManagerError> {
        Ok(self.get_all_keys_internal().await?.1)
    }

    /// Every key not yet retired, for validation and JWKS.
    #[tracing::instrument(name = "keys.all", skip_all)]
    pub async fn get_all_keys(&self) -> Result<Vec<KeyContainer>, KeyManagerError> {
        Ok(self.get_all_keys_internal().await?.0)
    }

    fn age(&self, created: DateTime<Utc>) -> chrono::Duration {
        let now = self.clock.now().max(created);
        now - created
    }

    fn algorithm(&self, name: &str) -> Option<&SigningAlgorithmOptions> {
        self.options
            .signing_algorithms
            .iter()
            .find(|a| a.name == name)
    }

    fn allowed(&self, name: &str) -> bool {
        self.algorithm(name).is_some()
    }

    pub(crate) async fn get_all_keys_internal(
        &self,
    ) -> Result<(Vec<KeyContainer>, Vec<KeyContainer>), KeyManagerError> {
        let mut keys = self.get_all_keys_from_cache();
        if keys.is_empty() {
            keys = self.get_all_keys_from_store(true).await?;
        }
        let (mut signing_ok, mut signing) = self.try_get_all_current_signing_keys(&keys);
        let mut rotation_required = signing_ok && self.is_key_rotation_required(&keys);
        if !signing_ok || rotation_required {
            let _guard = tokio::time::timeout(NEW_KEY_LOCK_TIMEOUT, self.new_key_lock.lock())
                .await
                .map_err(|_| KeyManagerError::LockTimeout)?;
            // Another task may have created keys while this one waited.
            keys = self.get_all_keys_from_cache();
            if !signing_ok {
                (signing_ok, signing) = self.try_get_all_current_signing_keys(&keys);
            }
            if rotation_required {
                rotation_required = self.is_key_rotation_required(&keys);
            }
            if !signing_ok || rotation_required {
                keys = self.get_all_keys_from_store(true).await?;
                if !signing_ok {
                    (signing_ok, signing) = self.try_get_all_current_signing_keys(&keys);
                }
                if rotation_required {
                    rotation_required = self.is_key_rotation_required(&keys);
                }
                if !signing_ok || rotation_required {
                    (keys, signing) = self.create_new_keys_and_add_to_cache().await?;
                }
            }
        }
        if signing.is_empty() {
            return Err(KeyManagerError::NoKeys);
        }
        Ok((keys, signing))
    }

    /// Some algorithm lacks a key, or its newest key is within
    /// `propagation_time` of the end of its rotation interval.
    pub(crate) fn is_key_rotation_required(&self, all: &[KeyContainer]) -> bool {
        if all.is_empty() {
            return true;
        }
        let groups = group_by_algorithm(all);
        let complete = groups.len() == self.options.signing_algorithms.len()
            && groups.iter().all(|(alg, _)| self.allowed(alg));
        if !complete {
            return true;
        }
        for (_, keys) in groups {
            let Some(active) = self.get_current_signing_key(&keys) else {
                return true;
            };
            let newest = keys
                .iter()
                .filter(|k| k.created > active.created)
                .max_by_key(|k| k.created)
                .unwrap_or(&active);
            let remaining = seconds(self.options.rotation_interval.0) - self.age(newest.created);
            if remaining <= seconds(self.options.propagation_time.0) {
                return true;
            }
        }
        false
    }

    pub(crate) async fn create_and_store_new_key(
        &self,
        alg: &SigningAlgorithmOptions,
    ) -> Result<KeyContainer, KeyManagerError> {
        let now = self.clock.now();
        let failed = |message: String| KeyManagerError::Create {
            alg: alg.name.clone(),
            message,
        };
        let pkcs8 = generate_pkcs8(&alg.name, self.options.rsa_key_size)
            .map_err(|e| failed(e.to_string()))?;
        let certificate = if alg.use_x509_certificate {
            let not_after = now + seconds(self.options.key_retirement_age());
            Some(
                self_signed_certificate(
                    &alg.name,
                    &pkcs8,
                    &self.certificate_subject,
                    now,
                    not_after,
                )
                .map_err(|e| failed(e.to_string()))?,
            )
        } else {
            None
        };
        let id = crate::tokens::new_jwt_id();
        let key = LoadedKey::from_der(
            &id,
            &alg.name,
            &pkcs8,
            certificate.as_deref(),
            &KeyOrigin {
                key: "generated key".into(),
                cert: Some("generated certificate".into()),
            },
        )
        .map_err(|e| failed(e.to_string()))?;
        let protector = self
            .protector
            .as_deref()
            .filter(|_| self.options.data_protect_keys);
        let sealed = seal_key(
            &id,
            &alg.name,
            now,
            &pkcs8,
            certificate.as_deref(),
            protector,
        )
        .map_err(failed)?;
        self.store.store_key(sealed).await?;
        Ok(KeyContainer {
            id,
            algorithm: alg.name.clone(),
            created: now,
            key: Arc::new(key),
        })
    }

    pub(crate) fn get_all_keys_from_cache(&self) -> Vec<KeyContainer> {
        let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        match &*cache {
            Some(cached) if cached.expires > self.clock.now() => cached.keys.clone(),
            _ => Vec::new(),
        }
    }

    pub(crate) fn are_all_keys_within_initialization_duration(
        &self,
        keys: &[KeyContainer],
    ) -> bool {
        if self.options.initialization_duration.0 == 0 {
            return false;
        }
        self.filter_expired_keys(keys)
            .iter()
            .all(|k| self.age(k.created) <= seconds(self.options.initialization_duration.0))
    }

    /// Drops retired keys, deleting them from the store when configured.
    pub(crate) async fn filter_and_delete_retired_keys(
        &self,
        keys: Vec<SerializedKey>,
    ) -> Result<Vec<SerializedKey>, KeyManagerError> {
        let retirement = seconds(self.options.key_retirement_age());
        let (retired, live): (Vec<_>, Vec<_>) = keys
            .into_iter()
            .partition(|k| self.age(k.created) >= retirement);
        if !retired.is_empty() && self.options.delete_retired_keys {
            for key in &retired {
                self.store.delete_key(&key.id).await?;
            }
        }
        Ok(live)
    }

    pub(crate) fn filter_expired_keys(&self, keys: &[KeyContainer]) -> Vec<KeyContainer> {
        let rotation = seconds(self.options.rotation_interval.0);
        keys.iter()
            .filter(|k| self.age(k.created) < rotation)
            .cloned()
            .collect()
    }

    pub(crate) fn cache_keys(&self, keys: &[KeyContainer]) {
        if keys.is_empty() {
            return;
        }
        let duration = if self.are_all_keys_within_initialization_duration(keys) {
            self.options.initialization_key_cache_duration.0
        } else {
            self.options.key_cache_duration.0
        };
        if duration > 0 {
            *self.cache.lock().unwrap_or_else(|p| p.into_inner()) = Some(CachedKeys {
                keys: keys.to_vec(),
                expires: self.clock.now() + seconds(duration),
            });
        }
    }

    /// Unprotects stored keys, skipping unreadable ones and algorithms no
    /// longer configured; caches the result when `cache` is set.
    pub(crate) async fn get_all_keys_from_store(
        &self,
        cache: bool,
    ) -> Result<Vec<KeyContainer>, KeyManagerError> {
        let stored = self.store.load_keys().await?;
        if stored.is_empty() {
            return Ok(Vec::new());
        }
        let live = self.filter_and_delete_retired_keys(stored).await?;
        let keys: Vec<KeyContainer> = live
            .iter()
            .filter_map(|k| match self.unprotect(k) {
                Ok(container) => Some(container),
                Err(message) => {
                    tracing::error!(key_id = %k.id, %message, "skipping a stored signing key");
                    None
                }
            })
            .filter(|k| self.allowed(&k.algorithm))
            .collect();
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        if cache {
            self.cache_keys(&keys);
        }
        Ok(keys)
    }

    fn unprotect(&self, stored: &SerializedKey) -> Result<KeyContainer, String> {
        let json = if stored.data_protected {
            let protector = self
                .protector
                .as_ref()
                .ok_or("the key is protected but no data protection keys are configured")?;
            let plain = protector
                .unprotect(KEY_PROTECTION_PURPOSE, &stored.data)
                .map_err(|e| e.to_string())?;
            String::from_utf8(plain).map_err(|e| e.to_string())?
        } else {
            stored.data.clone()
        };
        let data: KeyData = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        let pkcs8 = STANDARD.decode(&data.pkcs8).map_err(|e| e.to_string())?;
        let certificate = data
            .certificate
            .map(|c| STANDARD.decode(c))
            .transpose()
            .map_err(|e| e.to_string())?;
        let origin = KeyOrigin {
            key: format!("stored key {}", stored.id),
            cert: Some(format!("stored certificate {}", stored.id)),
        };
        let key = LoadedKey::from_der(
            &stored.id,
            &stored.algorithm,
            &pkcs8,
            certificate.as_deref(),
            &origin,
        )
        .map_err(|e| e.to_string())?;
        Ok(KeyContainer {
            id: stored.id.clone(),
            algorithm: stored.algorithm.clone(),
            created: stored.created,
            key: Arc::new(key),
        })
    }

    pub(crate) async fn create_new_keys_and_add_to_cache(
        &self,
    ) -> Result<(Vec<KeyContainer>, Vec<KeyContainer>), KeyManagerError> {
        let mut keys = self.get_all_keys_from_cache();
        for alg in &self.options.signing_algorithms {
            keys.push(self.create_and_store_new_key(alg).await?);
        }
        if self.are_all_keys_within_initialization_duration(&keys) {
            // New deployment: give other instances time to create keys too,
            // then settle on whatever the store holds.
            let delay = self.options.initialization_synchronization_delay.0;
            if delay > 0 {
                tokio::time::sleep(Duration::from_secs(delay.unsigned_abs())).await;
            }
            keys = self.get_all_keys_from_store(false).await?;
        }
        self.cache_keys(&keys);
        let active = self.get_all_current_signing_keys(&keys);
        Ok((keys, active))
    }

    pub(crate) fn try_get_all_current_signing_keys(
        &self,
        keys: &[KeyContainer],
    ) -> (bool, Vec<KeyContainer>) {
        let signing = self.get_all_current_signing_keys(keys);
        let ok = signing.len() == self.options.signing_algorithms.len()
            && signing.iter().all(|k| self.allowed(&k.algorithm));
        (ok, signing)
    }

    pub(crate) fn get_all_current_signing_keys(&self, all: &[KeyContainer]) -> Vec<KeyContainer> {
        group_by_algorithm(all)
            .into_iter()
            .filter_map(|(_, keys)| self.get_current_signing_key(&keys))
            .collect()
    }

    /// The oldest key past its activation delay, or failing that the oldest
    /// usable key ignoring the delay (a brand-new deployment).
    pub(crate) fn get_current_signing_key(&self, keys: &[KeyContainer]) -> Option<KeyContainer> {
        self.get_current_signing_key_internal(keys, false)
            .or_else(|| self.get_current_signing_key_internal(keys, true))
    }

    pub(crate) fn get_current_signing_key_internal(
        &self,
        keys: &[KeyContainer],
        ignore_activation_delay: bool,
    ) -> Option<KeyContainer> {
        keys.iter()
            .filter(|k| self.can_be_used_as_current_signing_key(k, ignore_activation_delay))
            .min_by_key(|k| k.created)
            .cloned()
    }

    pub(crate) fn can_be_used_as_current_signing_key(
        &self,
        key: &KeyContainer,
        ignore_activation_delay: bool,
    ) -> bool {
        let Some(alg) = self.algorithm(&key.algorithm) else {
            return false;
        };
        if alg.use_x509_certificate && !key.has_x509_certificate() {
            return false;
        }
        let now = self.clock.now().max(key.created);
        let mut start = key.created;
        if !ignore_activation_delay {
            start += seconds(self.options.propagation_time.0);
        }
        if start > now {
            return false;
        }
        key.created + seconds(self.options.rotation_interval.0) >= now
    }
}

/// Keys grouped by algorithm, groups in first-seen order.
fn group_by_algorithm(keys: &[KeyContainer]) -> Vec<(String, Vec<KeyContainer>)> {
    let mut groups: Vec<(String, Vec<KeyContainer>)> = Vec::new();
    for key in keys {
        match groups.iter_mut().find(|(alg, _)| *alg == key.algorithm) {
            Some((_, group)) => group.push(key.clone()),
            None => groups.push((key.algorithm.clone(), vec![key.clone()])),
        }
    }
    groups
}
