//! Data protection with a master key ring: authenticated encryption
//! (AES-256-GCM) of values stored at rest, such as signing keys. Each
//! protected value names the key that sealed it, so the ring can rotate:
//! the first key protects, every key unprotects.
//!
//! Format: `v1.<key id>.<base64url nonce>.<base64url ciphertext and tag>`.
//! The purpose string is bound as associated data, so a value protected for
//! one purpose can't be unprotected for another.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Master keys are 32 random bytes.
pub const KEY_LEN: usize = 32;

const VERSION: &str = "v1";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DataProtectionError {
    #[error("data protection key {0} must be {KEY_LEN} bytes")]
    KeyLength(String),
    #[error("data protection key id {0:?} must be non-empty and contain no '.'")]
    KeyId(String),
    #[error("data protection key id {0} is configured more than once")]
    DuplicateKeyId(String),
    #[error("data protection needs at least one key")]
    NoKeys,
    #[error("the protected value is malformed")]
    Malformed,
    #[error("the protected value was sealed with unknown key {0}")]
    UnknownKey(String),
    #[error("the protected value failed authentication")]
    Tampered,
}

pub struct DataProtector {
    /// `(id, key)`, the protecting key first.
    keys: Vec<(String, LessSafeKey)>,
}

impl std::fmt::Debug for DataProtector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ids: Vec<&str> = self.keys.iter().map(|(id, _)| id.as_str()).collect();
        f.debug_struct("DataProtector")
            .field("key_ids", &ids)
            .finish()
    }
}

impl DataProtector {
    /// A ring from `(id, secret)` pairs; the first protects new values.
    pub fn new<'a>(
        keys: impl IntoIterator<Item = (&'a str, &'a [u8])>,
    ) -> Result<Self, DataProtectionError> {
        let mut ring: Vec<(String, LessSafeKey)> = Vec::new();
        for (id, secret) in keys {
            if id.is_empty() || id.contains('.') {
                return Err(DataProtectionError::KeyId(id.to_owned()));
            }
            if ring.iter().any(|(existing, _)| existing == id) {
                return Err(DataProtectionError::DuplicateKeyId(id.to_owned()));
            }
            if secret.len() != KEY_LEN {
                return Err(DataProtectionError::KeyLength(id.to_owned()));
            }
            let key = UnboundKey::new(&AES_256_GCM, secret)
                .map_err(|_| DataProtectionError::KeyLength(id.to_owned()))?;
            ring.push((id.to_owned(), LessSafeKey::new(key)));
        }
        if ring.is_empty() {
            return Err(DataProtectionError::NoKeys);
        }
        Ok(DataProtector { keys: ring })
    }

    /// Seals `plaintext` for `purpose` with the first key.
    pub fn protect(&self, purpose: &str, plaintext: &[u8]) -> String {
        let (id, key) = &self.keys[0];
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce)
            .expect("system random source");
        let mut sealed = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(purpose.as_bytes()),
            &mut sealed,
        )
        .expect("AES-GCM sealing cannot fail for in-memory buffers");
        format!(
            "{VERSION}.{id}.{}.{}",
            URL_SAFE_NO_PAD.encode(nonce),
            URL_SAFE_NO_PAD.encode(sealed)
        )
    }

    /// Opens a value sealed for `purpose` by any key in the ring.
    pub fn unprotect(
        &self,
        purpose: &str,
        protected: &str,
    ) -> Result<Vec<u8>, DataProtectionError> {
        let mut parts = protected.split('.');
        let (Some(VERSION), Some(id), Some(nonce), Some(sealed), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(DataProtectionError::Malformed);
        };
        let (_, key) = self
            .keys
            .iter()
            .find(|(candidate, _)| candidate == id)
            .ok_or_else(|| DataProtectionError::UnknownKey(id.to_owned()))?;
        let nonce: [u8; NONCE_LEN] = URL_SAFE_NO_PAD
            .decode(nonce)
            .ok()
            .and_then(|n| n.try_into().ok())
            .ok_or(DataProtectionError::Malformed)?;
        let mut sealed = URL_SAFE_NO_PAD
            .decode(sealed)
            .map_err(|_| DataProtectionError::Malformed)?;
        let opened = key
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(purpose.as_bytes()),
                &mut sealed,
            )
            .map_err(|_| DataProtectionError::Tampered)?;
        Ok(opened.to_vec())
    }
}

/// A new random master key.
pub fn generate_key() -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    SystemRandom::new()
        .fill(&mut key)
        .expect("system random source");
    key
}
