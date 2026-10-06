//! Secrets as admin manages them (shared by API resources and clients): the
//! stored hash, the input of a new secret, what reads show (never the
//! value), and stable ids for imported secrets that have none.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::EntityId;

/// How a secret's plaintext is hashed. Its name is read without regard
/// to case (`Sha256`, `SHA256`, `sha256`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Sha512,
}

impl<'de> Deserialize<'de> for HashAlgorithm {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        match name.to_ascii_lowercase().as_str() {
            "sha256" => Ok(HashAlgorithm::Sha256),
            "sha512" => Ok(HashAlgorithm::Sha512),
            _ => Err(serde::de::Error::unknown_variant(
                &name,
                &["Sha256", "Sha512"],
            )),
        }
    }
}

impl HashAlgorithm {
    /// The name stored with the secret.
    pub fn stored_name(self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "SHA256",
            HashAlgorithm::Sha512 => "SHA512",
        }
    }
}

/// Base64 of the SHA-256 or SHA-512 of the UTF-8 plaintext,
/// what the shared secret validator compares with.
pub fn hash_secret(plaintext: &str, algorithm: HashAlgorithm) -> String {
    let digest = match algorithm {
        HashAlgorithm::Sha256 => &aws_lc_rs::digest::SHA256,
        HashAlgorithm::Sha512 => &aws_lc_rs::digest::SHA512,
    };
    STANDARD.encode(aws_lc_rs::digest::digest(digest, plaintext.as_bytes()).as_ref())
}

/// The id of an imported secret that has none: a UUIDv8 from the SHA-256
/// of its type and value, so it is the same on every read and restart.
/// Two imported secrets of one resource with the same type and value share
/// the id, and deleting it removes both.
pub fn derived_secret_id(secret_type: &str, value: &str) -> EntityId {
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        format!("{secret_type}\u{0}{value}").as_bytes(),
    );
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_ref()[..16]);
    bytes[6] = 0x80 | (bytes[6] & 0x0f);
    bytes[8] = 0x80 | (bytes[8] & 0x3f);
    EntityId(bytes)
}

/// A client or API resource secret as the admin API shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretConfiguration {
    pub id: EntityId,
    pub description: Option<String>,
    pub expiration: Option<DateTime<Utc>>,
    #[serde(rename = "type")]
    pub secret_type: String,
}

/// The arguments of a create secret call.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateSecret {
    #[serde(default)]
    pub plaintext_value: String,
    #[serde(default)]
    pub hash_algorithm: Option<HashAlgorithm>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub expiration: Option<DateTime<Utc>>,
    #[serde(default, rename = "type")]
    pub secret_type: Option<String>,
}

/// Never the plaintext.
impl std::fmt::Debug for CreateSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateSecret")
            .field("plaintext_value", &"<redacted>")
            .field("hash_algorithm", &self.hash_algorithm)
            .field("description", &self.description)
            .field("expiration", &self.expiration)
            .field("secret_type", &self.secret_type)
            .finish()
    }
}

/// A stored secret's type (`SharedSecret` when absent).
fn stored_type(secret: &Value) -> String {
    secret
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("SharedSecret")
        .to_owned()
}

/// A stored secret's id: its own, or the derived one.
pub fn stored_id(secret: &Value) -> EntityId {
    secret
        .get("id")
        .and_then(Value::as_str)
        .and_then(|id| id.parse().ok())
        .unwrap_or_else(|| {
            derived_secret_id(
                &stored_type(secret),
                secret
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            )
        })
}

/// The stored secrets with every id written in.
pub fn with_ids(secrets: &[Value]) -> Vec<Value> {
    secrets
        .iter()
        .map(|secret| {
            let mut secret = secret.clone();
            let id = stored_id(&secret);
            if let Value::Object(object) = &mut secret {
                object.insert("id".into(), json!(id));
            }
            secret
        })
        .collect()
}

/// What reads show of a stored secret.
pub fn configuration(secret: &Value) -> SecretConfiguration {
    SecretConfiguration {
        id: stored_id(secret),
        description: secret
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned),
        // RFC 3339, or a zone-less form (UTC), as the secret loader reads it.
        expiration: secret
            .get("expiration")
            .and_then(Value::as_str)
            .and_then(|e| {
                DateTime::parse_from_rfc3339(e)
                    .map(|d| d.with_timezone(&Utc))
                    .ok()
                    .or_else(|| {
                        chrono::NaiveDateTime::parse_from_str(e, "%Y-%m-%dT%H:%M:%S%.f")
                            .ok()
                            .map(|n| n.and_utc())
                    })
            }),
        secret_type: stored_type(secret),
    }
}

/// A new secret as stored, with a fresh id.
pub fn new_secret(input: &CreateSecret) -> (EntityId, Value) {
    let id = EntityId::new_v7();
    let algorithm = input.hash_algorithm.unwrap_or_default();
    let secret = json!({
        "id": id,
        "value": hash_secret(&input.plaintext_value, algorithm),
        "description": input.description,
        "expiration": input.expiration,
        "type": input.secret_type.as_deref().unwrap_or("SharedSecret"),
        "hashAlgorithm": algorithm.stored_name(),
    });
    (id, secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_algorithm_names_ignore_case() {
        for name in ["Sha256", "SHA256", "sha256"] {
            let parsed: HashAlgorithm = serde_json::from_value(serde_json::json!(name)).unwrap();
            assert_eq!(parsed, HashAlgorithm::Sha256, "{name}");
        }
        let parsed: HashAlgorithm = serde_json::from_value(serde_json::json!("sha512")).unwrap();
        assert_eq!(parsed, HashAlgorithm::Sha512);
        assert!(serde_json::from_value::<HashAlgorithm>(serde_json::json!("md5")).is_err());
    }

    #[test]
    fn a_secret_to_create_never_shows_its_plaintext() {
        let input: CreateSecret =
            serde_json::from_value(serde_json::json!({ "plaintextValue": "hunter2" })).unwrap();
        assert!(!format!("{input:?}").contains("hunter2"));
    }
}
