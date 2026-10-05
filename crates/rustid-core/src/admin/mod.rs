//! The admin model (what the admin services take and return):
//! entity ids (UUIDv7, distinct from natural keys), versions for optimistic
//! concurrency, and errors with stable codes and messages.

pub mod api_resources;
pub mod clients;
pub mod query;
pub mod resources;
pub mod schemas;
pub mod secrets;

use std::fmt;
use std::str::FromStr;

use crate::stores::StoreError;

/// An entity or secret id: a UUIDv7 (RFC 9562), time-ordered.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntityId(pub [u8; 16]);

impl EntityId {
    /// 48 bits of Unix milliseconds, version 7, 74 random bits.
    pub fn new_v7() -> EntityId {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let random = crate::data_protection::generate_key();
        let mut bytes = [0u8; 16];
        bytes[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
        bytes[6..].copy_from_slice(&random[..10]);
        bytes[6] = 0x70 | (bytes[6] & 0x0f);
        bytes[8] = 0x80 | (bytes[8] & 0x3f);
        EntityId(bytes)
    }
}

impl fmt::Display for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for EntityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Not a hyphenated UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidEntityId;

impl FromStr for EntityId {
    type Err = InvalidEntityId;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let groups: Vec<&str> = text.split('-').collect();
        let lengths: Vec<usize> = groups.iter().map(|g| g.len()).collect();
        if lengths != [8, 4, 4, 4, 12] {
            return Err(InvalidEntityId);
        }
        let hex: String = groups.concat();
        let mut bytes = [0u8; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2).ok_or(InvalidEntityId)?, 16)
                .map_err(|_| InvalidEntityId)?;
        }
        Ok(EntityId(bytes))
    }
}

impl serde::Serialize for EntityId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for EntityId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse()
            .map_err(|_| serde::de::Error::custom("not a UUID"))
    }
}

/// A machine-readable code, a message, and the properties
/// it concerns.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminError {
    pub code: &'static str,
    pub message: String,
    pub property_names: Vec<String>,
}

impl AdminError {
    fn new(code: &'static str, message: String, property_names: Vec<String>) -> Self {
        AdminError {
            code,
            message,
            property_names,
        }
    }

    pub fn already_exists(kind: &str, key: &str) -> Self {
        Self::new(
            "already_exists",
            format!("{kind} '{key}' already exists."),
            Vec::new(),
        )
    }

    pub fn not_found(kind: &str, id: &str) -> Self {
        Self::new(
            "not_found",
            format!("{kind} '{id}' was not found."),
            Vec::new(),
        )
    }

    pub fn version_conflict() -> Self {
        Self::new(
            "version_conflict",
            "The item has been modified by another operation. Please refresh and try again."
                .to_owned(),
            Vec::new(),
        )
    }

    pub fn validation_failed(message: impl Into<String>) -> Self {
        Self::new("validation_failed", message.into(), Vec::new())
    }

    /// `validation_failed` about one property.
    pub fn validation_failed_on(property: &str, message: impl Into<String>) -> Self {
        Self::new(
            "validation_failed",
            message.into(),
            vec![property.to_owned()],
        )
    }

    pub fn required(property: &str) -> Self {
        Self::new(
            "required",
            "A value is required.".to_owned(),
            vec![property.to_owned()],
        )
    }

    pub fn invalid_value(property: &str, message: impl Into<String>) -> Self {
        Self::new("invalid_value", message.into(), vec![property.to_owned()])
    }
}

/// A successful save: the entity's id and its new version (0 for a delete).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Saved {
    pub id: EntityId,
    pub version: i32,
}

/// `SaveResult`: saved, or the errors that refused it. The outer error is a
/// store failure.
pub type SaveResult = Result<Result<Saved, Vec<AdminError>>, StoreError>;

/// An item with its id and version.
#[derive(Debug, Clone, PartialEq)]
pub struct Versioned<T> {
    pub id: EntityId,
    pub version: i32,
    pub item: T,
}
