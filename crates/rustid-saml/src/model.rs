//! The SAML service provider model (the SAML service provider and its
//! parts), read from the shared fixture format: camelCase, time span
//! text, enums by name or number, certificates as PEM or base64 DER.

use std::collections::BTreeMap;
use std::path::Path;

use rustid_core::options::TimeSpan;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// An enum from its name (any case) or number.
fn enum_name_or_value<'de, D: Deserializer<'de>, T: Copy>(
    deserializer: D,
    variants: &[(&str, i64, T)],
    what: &str,
) -> Result<T, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    let found = match &value {
        serde_json::Value::String(name) => variants
            .iter()
            .find(|(n, _, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, _, v)| *v),
        serde_json::Value::Number(n) => n
            .as_i64()
            .and_then(|n| variants.iter().find(|(_, num, _)| *num == n))
            .map(|(_, _, v)| *v),
        _ => None,
    };
    found.ok_or_else(|| {
        let names: Vec<&str> = variants.iter().map(|(n, _, _)| *n).collect();
        serde::de::Error::custom(format!(
            "{what} must be one of {}, not {value}",
            names.join(", ")
        ))
    })
}

/// A SAML binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    HttpRedirect,
    HttpPost,
}

impl Binding {
    const VARIANTS: [(&'static str, i64, Binding); 2] = [
        ("HttpRedirect", 0, Binding::HttpRedirect),
        ("HttpPost", 1, Binding::HttpPost),
    ];

    pub fn name(self) -> &'static str {
        match self {
            Binding::HttpRedirect => "HttpRedirect",
            Binding::HttpPost => "HttpPost",
        }
    }

    /// The binding's URI in SAML messages and metadata.
    pub fn uri(self) -> &'static str {
        match self {
            Binding::HttpRedirect => crate::constants::BINDING_REDIRECT,
            Binding::HttpPost => crate::constants::BINDING_POST,
        }
    }
}

impl<'de> Deserialize<'de> for Binding {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        enum_name_or_value(d, &Self::VARIANTS, "binding")
    }
}

impl Serialize for Binding {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

/// `KeyUse`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyUse {
    #[default]
    Signing,
    Encryption,
}

impl<'de> Deserialize<'de> for KeyUse {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        enum_name_or_value(
            d,
            &[
                ("Signing", 0, KeyUse::Signing),
                ("Encryption", 1, KeyUse::Encryption),
            ],
            "use",
        )
    }
}

impl Serialize for KeyUse {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            KeyUse::Signing => "Signing",
            KeyUse::Encryption => "Encryption",
        })
    }
}

/// What a response signs (flags: response 1, assertion 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigningBehavior {
    DoNotSign,
    SignResponse,
    #[default]
    SignAssertion,
    SignBoth,
}

impl SigningBehavior {
    pub fn name(self) -> &'static str {
        match self {
            SigningBehavior::DoNotSign => "DoNotSign",
            SigningBehavior::SignResponse => "SignResponse",
            SigningBehavior::SignAssertion => "SignAssertion",
            SigningBehavior::SignBoth => "SignBoth",
        }
    }

    pub fn signs_response(self) -> bool {
        matches!(
            self,
            SigningBehavior::SignResponse | SigningBehavior::SignBoth
        )
    }

    pub fn signs_assertion(self) -> bool {
        matches!(
            self,
            SigningBehavior::SignAssertion | SigningBehavior::SignBoth
        )
    }
}

impl<'de> Deserialize<'de> for SigningBehavior {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        enum_name_or_value(
            d,
            &[
                ("DoNotSign", 0, SigningBehavior::DoNotSign),
                ("SignResponse", 1, SigningBehavior::SignResponse),
                ("SignAssertion", 2, SigningBehavior::SignAssertion),
                ("SignBoth", 3, SigningBehavior::SignBoth),
            ],
            "signingBehavior",
        )
    }
}

impl Serialize for SigningBehavior {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.name())
    }
}

/// A service provider endpoint's kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Endpoint {
    pub location: String,
    pub binding: Binding,
}

/// `IndexedEndpoint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedEndpoint {
    pub location: String,
    pub binding: Binding,
    #[serde(default)]
    pub index: i32,
    #[serde(default)]
    pub is_default: bool,
}

/// The certificate (DER) and what it's for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpCertificate {
    pub der: Vec<u8>,
    pub key_use: KeyUse,
}

#[derive(Deserialize, Serialize)]
struct RawCertificate {
    certificate: String,
    #[serde(default, rename = "use")]
    key_use: KeyUse,
}

/// A certificate as PEM, or base64 DER (whitespace ignored), checked to
/// parse as X.509.
pub fn decode_certificate(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let der = if text.contains("-----BEGIN") {
        pem::parse(text).map_err(|e| e.to_string())?.into_contents()
    } else {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|e| format!("not PEM or base64: {e}"))?
    };
    use x509_parser::prelude::FromDer;
    x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|e| format!("not an X.509 certificate: {e}"))?;
    Ok(der)
}

impl<'de> Deserialize<'de> for SpCertificate {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = RawCertificate::deserialize(d)?;
        let der = decode_certificate(&raw.certificate)
            .map_err(|e| serde::de::Error::custom(format!("certificate: {e}")))?;
        Ok(SpCertificate {
            der,
            key_use: raw.key_use,
        })
    }
}

impl Serialize for SpCertificate {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        RawCertificate {
            certificate: base64::engine::general_purpose::STANDARD.encode(&self.der),
            key_use: self.key_use,
        }
        .serialize(s)
    }
}

fn unspecified_name_id_format() -> Option<String> {
    Some(crate::constants::NAME_ID_UNSPECIFIED.to_owned())
}

fn yes() -> bool {
    true
}

/// The saml service provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceProvider {
    pub entity_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub clock_skew: Option<TimeSpan>,
    #[serde(default)]
    pub request_max_age: Option<TimeSpan>,
    #[serde(default)]
    pub assertion_lifetime: Option<TimeSpan>,
    #[serde(default)]
    pub assertion_consumer_service_urls: Vec<IndexedEndpoint>,
    #[serde(default)]
    pub single_logout_service_urls: Vec<Endpoint>,
    #[serde(default)]
    pub require_signed_authn_requests: Option<bool>,
    #[serde(default)]
    pub require_signed_logout_responses: Option<bool>,
    #[serde(default)]
    pub certificates: Vec<SpCertificate>,
    #[serde(default)]
    pub allow_idp_initiated: bool,
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    #[serde(default)]
    pub claim_mappings: BTreeMap<String, String>,
    #[serde(default)]
    pub authn_context_mappings: BTreeMap<String, String>,
    #[serde(default)]
    pub requested_claim_types: Vec<String>,
    /// Defaults to `unspecified`; an explicit null clears it.
    #[serde(default = "unspecified_name_id_format")]
    pub default_name_id_format: Option<String>,
    #[serde(default)]
    pub email_name_id_claim_type: Option<String>,
    #[serde(default)]
    pub signing_behavior: Option<SigningBehavior>,
    #[serde(default)]
    pub allowed_signature_algorithms: Option<Vec<String>>,
}

/// A service provider file that can't be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ModelError(pub String);

/// Service providers from the fixture format; duplicate entity ids refuse to
/// load, as the in memory SAML service provider store refuses them.
pub fn parse_service_providers(text: &str) -> Result<Vec<ServiceProvider>, ModelError> {
    let values: Vec<serde_json::Value> =
        serde_json::from_str(text).map_err(|e| ModelError(e.to_string()))?;
    let mut sps = Vec::with_capacity(values.len());
    for value in values {
        let id = value
            .get("entityId")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("(no entityId)")
            .to_owned();
        let sp: ServiceProvider = serde_json::from_value(value)
            .map_err(|e| ModelError(format!("service provider {id}: {e}")))?;
        sps.push(sp);
    }
    let mut seen = std::collections::HashSet::new();
    if !sps.iter().all(|sp| seen.insert(sp.entity_id.as_str())) {
        return Err(ModelError(
            "Service providers must not contain duplicate entity IDs".into(),
        ));
    }
    Ok(sps)
}

pub fn load_service_providers(path: &Path) -> Result<Vec<ServiceProvider>, ModelError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| ModelError(format!("reading {}: {e}", path.display())))?;
    parse_service_providers(&text).map_err(|e| ModelError(format!("{}: {}", path.display(), e.0)))
}
