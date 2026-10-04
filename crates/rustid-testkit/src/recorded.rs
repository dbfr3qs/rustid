use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Response headers that take part in comparisons. Everything else (dates,
/// server banners, content-length) is dropped at recording time.
pub const RECORDED_HEADERS: &[&str] = &[
    "content-type",
    "location",
    "cache-control",
    "pragma",
    "www-authenticate",
    "vary",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
    "content-security-policy",
    "x-content-security-policy",
    "referrer-policy",
    // A DPoP server nonce: its presence compares, its value is masked.
    "dpop-nonce",
];

/// A response reduced to what comparisons care about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Recorded {
    pub status: u16,
    /// Lower-cased header names, only those in [`RECORDED_HEADERS`].
    pub headers: BTreeMap<String, String>,
    /// Every `Set-Cookie` header in order. Omitted from snapshots when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub set_cookies: Vec<String>,
    pub body: Body,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Body {
    Json(serde_json::Value),
    Text(String),
    Empty,
}
