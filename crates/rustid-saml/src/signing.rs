//! The IdP's signing key as an XML signer (the SAML signing service's
//! certificate with its private key): RSA keys sign RSA-SHA256, EC keys
//! ECDSA with their curve's hash.

use std::sync::Arc;

use rustid_core::keys::LoadedKey;

use crate::xml::dom::XmlError;
use crate::xml::dsig::{XmlSigner, algorithms as alg};

pub struct SamlKey {
    pub key: Arc<LoadedKey>,
    /// The key's X.509 certificate (DER).
    pub certificate: Vec<u8>,
}

impl XmlSigner for SamlKey {
    fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    fn signature_method(&self) -> &'static str {
        match self.key.alg.as_str() {
            _ if self.key.is_rsa() => alg::RSA_SHA256,
            "ES384" => alg::ECDSA_SHA384,
            "ES512" => alg::ECDSA_SHA512,
            _ => alg::ECDSA_SHA256,
        }
    }

    fn digest_method(&self) -> &'static str {
        match self.key.alg.as_str() {
            _ if self.key.is_rsa() => alg::SHA256,
            "ES384" => alg::SHA384,
            "ES512" => alg::SHA512,
            _ => alg::SHA256,
        }
    }

    fn sign_bytes(&self, data: &[u8]) -> Result<Vec<u8>, XmlError> {
        let signed = match self.key.sign_rsa_pkcs1_sha256(data) {
            Some(result) => result,
            // ES256/384/512 sign with their curve's hash, r || s.
            None => self.key.sign(data),
        };
        signed.map_err(|e| XmlError(e.to_string()))
    }
}
