//! Static keys from configuration combined
//! with automatically managed ones. Key management failures are
//! infrastructure failures and surface as `StoreError`s (HTTP 500).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::key_management::{KeyManager, KeyManagerError};
use crate::keys::{KeyMaterial, LoadedKey};
use crate::stores::StoreError;

#[derive(Debug, Clone, Default)]
pub struct KeyService {
    signing: Arc<[Arc<LoadedKey>]>,
    /// Static signing keys, then validation-only keys.
    validation: Arc<[Arc<LoadedKey>]>,
    manager: Option<Arc<KeyManager>>,
    /// The cache: certificates for managed RSA keys,
    /// by key id.
    saml_certificates: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

/// Why SAML can't list the signing certificates.
#[derive(Debug, thiserror::Error)]
pub enum SamlCertificateError {
    #[error("No signing credential available. Configure a signing certificate.")]
    NoSigningKey,
    #[error("Signing credential must be an X509 certificate or RSA key with private key.")]
    Unsupported,
    #[error(
        "Cannot auto-wrap a manually registered RSA key as an X509 certificate for SAML signing. Use an X509 certificate directly or enable automatic key management."
    )]
    StaticRsaKey,
    #[error("creating a SAML signing certificate for key {0} failed")]
    Certificate(String),
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// The rsa certificate factory.
const MAX_SAML_CERTIFICATES: usize = 10;

impl From<KeyManagerError> for StoreError {
    fn from(error: KeyManagerError) -> Self {
        match error {
            KeyManagerError::Store(e) => e,
            other => StoreError::Backend(other.to_string()),
        }
    }
}

impl KeyService {
    /// `manager` is `None` when key management is disabled.
    pub fn new(material: KeyMaterial, manager: Option<Arc<KeyManager>>) -> Self {
        let signing: Vec<Arc<LoadedKey>> = material.signing.into_iter().map(Arc::new).collect();
        let validation: Vec<Arc<LoadedKey>> = signing
            .iter()
            .cloned()
            .chain(material.validation_only.into_iter().map(Arc::new))
            .collect();
        KeyService {
            signing: signing.into(),
            validation: validation.into(),
            manager,
            saml_certificates: Arc::default(),
        }
    }

    /// The default signing
    /// key and its certificate (a managed RSA key's made as for metadata).
    pub async fn saml_signing_key(
        &self,
        issuer: &str,
    ) -> Result<(Arc<LoadedKey>, Vec<u8>), SamlCertificateError> {
        let key = self
            .signing_key(&[])
            .await?
            .ok_or(SamlCertificateError::NoSigningKey)?;
        if let Some(cert) = key.certificate() {
            return Ok((key, cert));
        }
        if !key.is_rsa() {
            return Err(SamlCertificateError::Unsupported);
        }
        // A managed key: the same certificate metadata publishes.
        let Some(manager) = &self.manager else {
            return Err(SamlCertificateError::StaticRsaKey);
        };
        let lifetime = chrono::Duration::seconds(manager.options().key_retirement_age());
        let container = manager
            .get_current_keys()
            .await
            .map_err(StoreError::from)?
            .into_iter()
            .find(|c| c.id == key.kid)
            .ok_or(SamlCertificateError::StaticRsaKey)?;
        let cert = self
            .managed_certificate(&container, issuer, lifetime)?
            .ok_or(SamlCertificateError::Unsupported)?;
        Ok((key, cert))
    }

    /// The certificate
    /// of every signing key, static then automatic. A managed RSA key
    /// without one gets the certificate (subject the
    /// SAML `issuer`); a static RSA key without one is an error; EC keys
    /// without one are skipped.
    pub async fn saml_signing_certificates(
        &self,
        issuer: &str,
    ) -> Result<Vec<Vec<u8>>, SamlCertificateError> {
        let mut out = Vec::new();
        for key in self.signing.iter() {
            match key.certificate() {
                Some(cert) => out.push(cert),
                None if key.is_rsa() => return Err(SamlCertificateError::StaticRsaKey),
                None => {}
            }
        }
        let Some(manager) = &self.manager else {
            return Ok(out);
        };
        let lifetime = chrono::Duration::seconds(manager.options().key_retirement_age());
        for container in manager.get_current_keys().await.map_err(StoreError::from)? {
            if let Some(cert) = container.key.certificate() {
                out.push(cert);
                continue;
            }
            if let Some(cert) = self.managed_certificate(&container, issuer, lifetime)? {
                out.push(cert);
            }
        }
        Ok(out)
    }

    /// The rsa certificate factory for a managed key: `None`
    /// for an EC key.
    fn managed_certificate(
        &self,
        container: &crate::key_management::KeyContainer,
        issuer: &str,
        lifetime: chrono::Duration,
    ) -> Result<Option<Vec<u8>>, SamlCertificateError> {
        if let Some(cert) = self
            .saml_certificates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&container.id)
        {
            return Ok(Some(cert.clone()));
        }
        let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, container.id.as_bytes());
        let mut serial = hash.as_ref()[..8].to_vec();
        serial[0] &= 0x7F; // RFC 5280: a positive serial
        let Some(cert) = container.key.rsa_certificate(
            issuer,
            &serial,
            container.created,
            container.created + lifetime,
        ) else {
            return Ok(None);
        };
        let cert = cert.map_err(|_| SamlCertificateError::Certificate(container.id.clone()))?;
        let mut cache = self
            .saml_certificates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cache.len() < MAX_SAML_CERTIFICATES {
            cache.insert(container.id.clone(), cert.clone());
        }
        Ok(Some(cert))
    }

    /// The signing key for `allowed_algorithms`: with no algorithms,
    /// the first static key, else the automatic key for the default
    /// algorithm; otherwise the first signing key with an allowed algorithm.
    pub async fn signing_key(
        &self,
        allowed: &[String],
    ) -> Result<Option<Arc<LoadedKey>>, StoreError> {
        if allowed.is_empty() {
            if let Some(key) = self.signing.first() {
                return Ok(Some(key.clone()));
            }
            let Some(manager) = &self.manager else {
                return Ok(None);
            };
            let default = manager
                .options()
                .signing_algorithms
                .first()
                .map(|a| a.name.clone());
            return Ok(manager
                .get_current_keys()
                .await?
                .into_iter()
                .find(|k| Some(&k.algorithm) == default.as_ref())
                .map(|k| k.key));
        }
        Ok(self
            .all_signing_keys()
            .await?
            .into_iter()
            .find(|k| allowed.contains(&k.alg)))
    }

    /// Static keys, then automatic ones.
    pub async fn all_signing_keys(&self) -> Result<Vec<Arc<LoadedKey>>, StoreError> {
        let mut keys: Vec<Arc<LoadedKey>> = self.signing.to_vec();
        if let Some(manager) = &self.manager {
            keys.extend(manager.get_current_keys().await?.into_iter().map(|k| k.key));
        }
        Ok(keys)
    }

    /// Every automatic key not yet retired
    /// (including announced ones), then static signing and validation keys.
    pub async fn validation_keys(&self) -> Result<Vec<Arc<LoadedKey>>, StoreError> {
        let mut keys: Vec<Arc<LoadedKey>> = Vec::new();
        if let Some(manager) = &self.manager {
            keys.extend(manager.get_all_keys().await?.into_iter().map(|k| k.key));
        }
        keys.extend(self.validation.iter().cloned());
        Ok(keys)
    }

    /// Distinct algorithms of the signing keys, in order.
    pub async fn signing_algorithms(&self) -> Result<Vec<String>, StoreError> {
        let mut algs: Vec<String> = Vec::new();
        for key in self.all_signing_keys().await? {
            if !algs.contains(&key.alg) {
                algs.push(key.alg.clone());
            }
        }
        Ok(algs)
    }
}
