//! `rustid-server import`: a migration bundle (configuration, signing
//! keys and grants exported from an existing database) into rustid's store. Grants arrive
//! as the source's model JSON and are translated into rustid's records here.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Duration, Utc};
use rustid_core::grants::PersistedGrant;
use rustid_core::issuance::AccessTokenRecord;
use rustid_core::tokens::{AccessToken, Claim};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The bundle's `format`.
pub const BUNDLE_FORMAT: &str = "rustid-migration-bundle";
/// The format's earlier name, still read.
const EARLIER_BUNDLE_FORMAT: &str = "rustid-ef-export";
/// The bundle version this server reads.
pub const BUNDLE_VERSION: u32 = 1;

/// A migration bundle (`docs/migration.md`).
#[derive(Debug, Deserialize, Serialize)]
pub struct Bundle {
    pub format: String,
    pub version: u32,
    pub exported_at: DateTime<Utc>,
    /// `fixtures/clients.json`'s format.
    pub clients: Vec<Value>,
    /// `fixtures/resources.json`'s format.
    pub resources: Value,
    /// `fixtures/saml-service-providers.json`'s format.
    #[serde(default)]
    pub saml_service_providers: Vec<Value>,
    pub signing_keys: Vec<BundleKey>,
    pub grants: Vec<GrantRow>,
    /// What the export left out, by kind.
    #[serde(default)]
    pub skipped: BTreeMap<String, u64>,
}

/// A signing key, unprotected.
#[derive(Debug, Deserialize, Serialize)]
pub struct BundleKey {
    pub id: String,
    pub algorithm: String,
    pub created: DateTime<Utc>,
    /// PKCS#8, base64.
    pub pkcs8: String,
    /// The certificate (DER, base64), for X.509 keys.
    pub certificate: Option<String>,
}

/// A bundle grant, its `data` parsed: a refresh token, a reference token or
/// a consent, in the bundle's JSON form.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GrantRow {
    pub key: String,
    #[serde(rename = "type")]
    pub grant_type: String,
    pub subject_id: Option<String>,
    pub session_id: Option<String>,
    pub client_id: String,
    pub description: Option<String>,
    pub creation_time: DateTime<Utc>,
    pub expiration: Option<DateTime<Utc>>,
    pub consumed_time: Option<DateTime<Utc>>,
    pub data: Value,
}

/// A grant that couldn't be translated, by its key.
#[derive(Debug, thiserror::Error)]
#[error("grant {key}: {message}")]
pub struct ImportError {
    pub key: String,
    pub message: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BundleClaim {
    #[serde(rename = "Type")]
    claim_type: String,
    value: String,
    #[serde(default)]
    value_type: Option<String>,
}

impl From<BundleClaim> for Claim {
    fn from(c: BundleClaim) -> Claim {
        Claim {
            claim_type: c.claim_type,
            value: c.value,
            // The claim converter leaves out the default (string) value type.
            value_type: c
                .value_type
                .unwrap_or_else(|| rustid_core::clients::CLAIM_VALUE_TYPE_STRING.to_owned()),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BundlePrincipal {
    #[serde(default)]
    claims: Vec<BundleClaim>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BundleToken {
    #[serde(default)]
    audiences: Vec<String>,
    issuer: String,
    creation_time: DateTime<Utc>,
    lifetime: i64,
    client_id: String,
    #[serde(default)]
    confirmation: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    claims: Vec<BundleClaim>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BundleRefreshToken {
    creation_time: DateTime<Utc>,
    lifetime: i64,
    #[serde(default)]
    consumed_time: Option<DateTime<Utc>>,
    /// Pre-v5 tokens kept one access token here.
    #[serde(default)]
    access_token: Option<BundleToken>,
    #[serde(default)]
    access_tokens: BTreeMap<String, BundleToken>,
    subject: BundlePrincipal,
    client_id: String,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    authorized_scopes: Vec<String>,
    #[serde(default)]
    authorized_resource_indicators: Option<Vec<String>>,
    /// `ProofType` as its number (None, ClientCertificate, DPoP).
    #[serde(default)]
    proof_type: Option<u8>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct BundleConsent {
    subject_id: String,
    client_id: String,
    #[serde(default)]
    scopes: Option<Vec<String>>,
    creation_time: DateTime<Utc>,
    #[serde(default)]
    expiration: Option<DateTime<Utc>>,
}

fn parse<T: serde::de::DeserializeOwned>(row: &GrantRow) -> Result<T, ImportError> {
    serde_json::from_value(row.data.clone()).map_err(|e| ImportError {
        key: row.key.clone(),
        message: e.to_string(),
    })
}

fn grant(row: &GrantRow, grant_type: &str, data: String) -> PersistedGrant {
    PersistedGrant {
        key: row.key.clone(),
        grant_type: grant_type.to_owned(),
        client_id: row.client_id.clone(),
        subject_id: row.subject_id.clone(),
        session_id: row.session_id.clone(),
        description: row.description.clone(),
        creation_time: row.creation_time,
        expiration: row.expiration,
        consumed_time: row.consumed_time,
        data,
    }
}

/// The access token rustid stores beside a refresh token: every claim
/// inline, `jti` apart, as `Token` holds it.
fn access_token(token: BundleToken) -> AccessTokenRecord {
    let claims: Vec<Claim> = token.claims.into_iter().map(Claim::from).collect();
    let jti = claims
        .iter()
        .find(|c| c.claim_type == "jti")
        .map(|c| c.value.clone());
    AccessTokenRecord {
        token: AccessToken {
            issuer: token.issuer,
            client_id: token.client_id,
            lifetime: token.lifetime,
            audiences: token.audiences,
            claims: claims
                .into_iter()
                .filter(|c| c.claim_type != "jti")
                .collect(),
            confirmation: token.confirmation,
        },
        jti,
    }
}

/// The claims a session models as fields rather than in `claims`.
const SESSION_FIELDS: &[&str] = &["sub", "sid", "auth_time", "idp", "amr"];

/// A refresh token's subject as the user session rustid keeps in the token.
fn user_session(
    principal: BundlePrincipal,
    session_id: Option<&str>,
    issued: DateTime<Utc>,
    expires: DateTime<Utc>,
) -> Result<rustid_core::session::UserSession, String> {
    let claims: Vec<Claim> = principal.claims.into_iter().map(Claim::from).collect();
    let first = |t: &str| {
        claims
            .iter()
            .find(|c| c.claim_type == t)
            .map(|c| c.value.clone())
    };
    let subject_id = first("sub").ok_or("the subject has no sub claim")?;
    let auth_time = match first("auth_time") {
        Some(value) => value
            .parse::<i64>()
            .map_err(|_| format!("auth_time {value:?} is not a number"))?,
        None => issued.timestamp(),
    };
    Ok(rustid_core::session::UserSession {
        subject_id,
        session_id: first("sid")
            .or_else(|| session_id.map(str::to_owned))
            .unwrap_or_default(),
        auth_time,
        idp: first("idp").unwrap_or_else(|| "local".to_owned()),
        amr: claims
            .iter()
            .filter(|c| c.claim_type == "amr")
            .map(|c| c.value.clone())
            .collect(),
        claims: claims
            .iter()
            .filter(|c| !SESSION_FIELDS.contains(&c.claim_type.as_str()))
            .cloned()
            .collect(),
        client_ids: Vec::new(),
        saml_sessions: Vec::new(),
        issued,
        expires,
        persistent: false,
        allow_refresh: None,
        force_renewal: false,
        issuer: None,
        key: None,
        upstream_id_token: None,
        upstream_sid: None,
    })
}

/// A bundle `RefreshToken` grant as rustid's refresh token record.
pub fn translate_refresh_token(row: &GrantRow) -> Result<PersistedGrant, ImportError> {
    use rustid_core::refresh_tokens::{ProofType, REFRESH_TOKEN, RefreshToken};
    let source: BundleRefreshToken = parse(row)?;
    let error = |message: String| ImportError {
        key: row.key.clone(),
        message,
    };
    let expires = source.creation_time + Duration::seconds(source.lifetime);
    let subject = user_session(
        source.subject,
        source.session_id.as_deref(),
        source.creation_time,
        expires,
    )
    .map_err(error)?;
    let mut tokens = source.access_tokens;
    let default = tokens.remove("").or(source.access_token).map(access_token);
    let token = RefreshToken {
        requested_claims: Default::default(),
        client_id: source.client_id,
        subject,
        session_id: source.session_id,
        description: source.description,
        authorized_scopes: source.authorized_scopes,
        authorized_resource_indicators: source.authorized_resource_indicators,
        access_token: default,
        resource_access_tokens: tokens
            .into_iter()
            .map(|(resource, token)| (resource, access_token(token)))
            .collect(),
        creation_time: source.creation_time,
        lifetime: source.lifetime,
        consumed_time: source.consumed_time,
        proof_type: match source.proof_type {
            Some(1) => Some(ProofType::ClientCertificate),
            Some(2) => Some(ProofType::DPoP),
            _ => None,
        },
    };
    let data = serde_json::to_string(&token).map_err(|e| error(e.to_string()))?;
    Ok(grant(row, REFRESH_TOKEN, data))
}

/// A bundle reference token (`Token`) as rustid's.
pub fn translate_reference_token(row: &GrantRow) -> Result<PersistedGrant, ImportError> {
    use rustid_core::reference_tokens::ReferenceToken;
    let source: BundleToken = parse(row)?;
    let claims: Vec<Claim> = source.claims.into_iter().map(Claim::from).collect();
    let first = |t: &str| {
        claims
            .iter()
            .find(|c| c.claim_type == t)
            .map(|c| c.value.clone())
    };
    let token = ReferenceToken {
        issuer: source.issuer,
        client_id: source.client_id,
        audiences: source.audiences,
        creation_time: source.creation_time,
        lifetime: source.lifetime,
        subject_id: first("sub"),
        session_id: first("sid"),
        description: source.description.or_else(|| row.description.clone()),
        confirmation: source.confirmation,
        claims: claims
            .into_iter()
            .filter(|c| !["iss", "nbf", "iat", "exp", "aud"].contains(&c.claim_type.as_str()))
            .collect(),
    };
    let data = serde_json::to_string(&token).map_err(|e| ImportError {
        key: row.key.clone(),
        message: e.to_string(),
    })?;
    Ok(grant(row, &row.grant_type, data))
}

/// A bundle `Consent` as rustid's.
pub fn translate_consent(row: &GrantRow) -> Result<PersistedGrant, ImportError> {
    use rustid_core::consent::{USER_CONSENT, UserConsent};
    let source: BundleConsent = parse(row)?;
    let consent = UserConsent {
        subject_id: source.subject_id,
        client_id: source.client_id,
        scopes: source.scopes.unwrap_or_default(),
        creation_time: source.creation_time,
        expiration: source.expiration,
    };
    let data = serde_json::to_string(&consent).map_err(|e| ImportError {
        key: row.key.clone(),
        message: e.to_string(),
    })?;
    Ok(grant(row, USER_CONSENT, data))
}

/// What `run` did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub clients: usize,
    pub resources: usize,
    pub saml_service_providers: usize,
    pub keys_stored: usize,
    /// Keys already in the store (an earlier import).
    pub keys_existing: usize,
    pub grants: usize,
    /// What the export left out, by kind.
    pub skipped: BTreeMap<String, u64>,
    pub warnings: Vec<String>,
}

impl std::fmt::Display for ImportReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "clients: {}", self.clients)?;
        writeln!(f, "resources: {}", self.resources)?;
        writeln!(f, "saml service providers: {}", self.saml_service_providers)?;
        writeln!(
            f,
            "signing keys: {} stored, {} already present",
            self.keys_stored, self.keys_existing
        )?;
        writeln!(f, "grants: {}", self.grants)?;
        for (kind, count) in &self.skipped {
            writeln!(f, "not migrated: {count} {kind}")?;
        }
        for warning in &self.warnings {
            writeln!(f, "warning: {warning}")?;
        }
        Ok(())
    }
}

/// Reads and checks a bundle.
pub fn read_bundle(path: &std::path::Path) -> anyhow::Result<Bundle> {
    use anyhow::Context;
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let head: Value =
        serde_json::from_str(&text).with_context(|| format!("{} is not JSON", path.display()))?;
    let format = head.get("format").and_then(Value::as_str).unwrap_or("");
    anyhow::ensure!(
        format == BUNDLE_FORMAT || format == EARLIER_BUNDLE_FORMAT,
        "{} is a {format:?} file, not a {BUNDLE_FORMAT} bundle",
        path.display()
    );
    let version = head.get("version").and_then(Value::as_u64).unwrap_or(0);
    anyhow::ensure!(
        version == u64::from(BUNDLE_VERSION),
        "{} is bundle version {version}; this server reads version {BUNDLE_VERSION}",
        path.display()
    );
    serde_json::from_value(head).with_context(|| format!("reading the bundle {}", path.display()))
}

/// Writes `value` as pretty JSON to `dir/name`.
fn write_json(
    dir: &std::path::Path,
    name: &str,
    value: &impl Serialize,
) -> anyhow::Result<PathBuf> {
    use anyhow::Context;
    let path = dir.join(name);
    std::fs::write(&path, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Validates the configuration the way the server loads it: through the
/// same loaders, from files in `dir`.
fn validate_configuration(bundle: &Bundle, dir: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::Context;
    rustid_core::clients::Clients::load(&write_json(dir, "clients.json", &bundle.clients)?)
        .context("the bundle's clients")?;
    rustid_core::resources::Resources::load(&write_json(dir, "resources.json", &bundle.resources)?)
        .context("the bundle's resources")?;
    rustid_saml::model::load_service_providers(&write_json(
        dir,
        "saml-service-providers.json",
        &bundle.saml_service_providers,
    )?)
    .context("the bundle's SAML service providers")?;
    Ok(())
}

fn count_resources(resources: &Value) -> usize {
    resources
        .as_object()
        .map(|o| o.values().filter_map(Value::as_array).map(Vec::len).sum())
        .unwrap_or(0)
}

/// Every grant translated; a grant of a kind rustid doesn't import is an
/// error (the export leaves those out).
fn translate_grants(bundle: &Bundle) -> anyhow::Result<Vec<PersistedGrant>> {
    bundle
        .grants
        .iter()
        .map(|row| match row.grant_type.as_str() {
            "refresh_token" => Ok(translate_refresh_token(row)?),
            "reference_token" => Ok(translate_reference_token(row)?),
            "user_consent" => Ok(translate_consent(row)?),
            other => anyhow::bail!("grant {}: {other} grants aren't imported", row.key),
        })
        .collect()
}

/// Imports `bundle` into the configured store. With the memory store,
/// whose grants live in process memory, `out_dir` receives the files the
/// server loads instead (configuration and keys; grants need Postgres).
pub async fn run(
    config: &crate::config::ServerConfig,
    bundle: &std::path::Path,
    out_dir: Option<&std::path::Path>,
) -> anyhow::Result<ImportReport> {
    use anyhow::Context;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use rustid_core::stores::PersistedGrantStore;

    let bundle = read_bundle(bundle)?;
    let postgres = config.store.kind == crate::config::StoreKind::Postgres;
    anyhow::ensure!(
        postgres || out_dir.is_some(),
        "the memory store keeps grants in process memory: import into Postgres, or pass \
         --out-dir to write the configuration and keys as files for the memory store"
    );
    anyhow::ensure!(
        !postgres || out_dir.is_none(),
        "--out-dir writes files for the memory store; with the Postgres store, import without it"
    );

    let key_management = &config.protocol.key_management;
    let protector = config.data_protector()?;
    anyhow::ensure!(
        bundle.signing_keys.is_empty() || !key_management.data_protect_keys || protector.is_some(),
        "data_protection.keys must be configured to protect the imported signing keys"
    );
    let protector = protector.filter(|_| key_management.data_protect_keys);

    let mut report = ImportReport {
        clients: bundle.clients.len(),
        resources: count_resources(&bundle.resources),
        saml_service_providers: bundle.saml_service_providers.len(),
        skipped: bundle.skipped.clone(),
        ..Default::default()
    };
    let configured = |alg: &str| {
        key_management
            .signing_algorithms
            .iter()
            .find(|a| a.name == alg)
    };
    for key in &bundle.signing_keys {
        if !key_management.enabled {
            report.warnings.push(format!(
                "signing key {} is stored, but key management is off: it isn't published or used",
                key.id
            ));
        } else if let Some(alg) = configured(&key.algorithm) {
            if alg.use_x509_certificate && key.certificate.is_none() {
                report.warnings.push(format!(
                    "signing key {} ({}) has no certificate, but use_x509_certificate is on for \
                     {}: it validates tokens but never signs",
                    key.id, key.algorithm, key.algorithm
                ));
            }
        } else {
            report.warnings.push(format!(
                "signing key {} ({}) is stored, but key management isn't configured for {}: \
                 add it to protocol.key_management.signing_algorithms to publish it",
                key.id, key.algorithm, key.algorithm
            ));
        }
    }
    let sealed = bundle
        .signing_keys
        .iter()
        .map(|key| {
            let pkcs8 = STANDARD
                .decode(&key.pkcs8)
                .with_context(|| format!("signing key {}: pkcs8", key.id))?;
            let certificate = key
                .certificate
                .as_deref()
                .map(|c| STANDARD.decode(c))
                .transpose()
                .with_context(|| format!("signing key {}: certificate", key.id))?;
            rustid_core::key_management::seal_key(
                &key.id,
                &key.algorithm,
                key.created,
                &pkcs8,
                certificate.as_deref(),
                protector.as_ref(),
            )
            .map_err(|e| anyhow::anyhow!("signing key {}: {e}", key.id))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    if let Some(out) = out_dir {
        if !bundle.grants.is_empty() {
            report.warnings.push(format!(
                "{} grants (refresh tokens, reference tokens, consents) aren't imported: the \
                 memory store keeps grants in process memory; import into Postgres to keep them",
                bundle.grants.len()
            ));
        }
        // Checked aside first: a bundle that fails leaves the output
        // directory as it was.
        let scratch = tempfile::tempdir().context("creating a scratch directory")?;
        validate_configuration(&bundle, scratch.path())?;
        std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
        validate_configuration(&bundle, out)?;
        let keys = std::sync::Arc::new(rustid_store_memory::FileSystemSigningKeyStore::new(
            out.join("keys"),
        ));
        store_keys(keys.as_ref(), &sealed, &mut report).await?;
        return Ok(report);
    }

    let pg = config
        .store
        .postgres
        .as_ref()
        .context("store.postgres is required for the postgres store")?;
    let scratch = tempfile::tempdir().context("creating a scratch directory")?;
    validate_configuration(&bundle, scratch.path())?;
    let grants = translate_grants(&bundle)?;
    let store = crate::open_postgres(pg).await?;
    store
        .import_clients(&bundle.clients)
        .await
        .context("importing clients")?;
    store
        .import_resources(&bundle.resources)
        .await
        .context("importing resources")?;
    store
        .import_saml_service_providers(&bundle.saml_service_providers)
        .await
        .context("importing SAML service providers")?;
    store_keys(&store, &sealed, &mut report).await?;
    for grant in grants {
        let key = grant.key.clone();
        store
            .store(grant)
            .await
            .with_context(|| format!("storing grant {key}"))?;
        report.grants += 1;
    }
    Ok(report)
}

/// Stores each key; one already present (an earlier import) is counted, not
/// replaced.
async fn store_keys(
    store: &dyn rustid_core::stores::SigningKeyStore,
    sealed: &[rustid_core::stores::SerializedKey],
    report: &mut ImportReport,
) -> anyhow::Result<()> {
    use rustid_core::stores::StoreError;
    for key in sealed {
        match store.store_key(key.clone()).await {
            Ok(()) => report.keys_stored += 1,
            Err(StoreError::DuplicateKey(_)) => report.keys_existing += 1,
            Err(e) => anyhow::bail!("storing signing key {}: {e}", key.id),
        }
    }
    Ok(())
}
