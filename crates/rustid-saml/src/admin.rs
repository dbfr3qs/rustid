//! SAML service provider admin (`SamlServiceProviderAdmin`): the
//! structure checks, then the configuration validator, then the extended
//! properties against schema `saml-service-provider`. The stored data is the
//! runtime `ServiceProvider` (the `service_providers_file` format); its
//! certificates also carry their admin `id`, and it carries
//! `extendedProperties`.

use std::collections::{BTreeMap, HashSet};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use rustid_core::admin::query::{Direction, QueryResult, Range, paginate};
use rustid_core::admin::schemas::{self, SAML_SERVICE_PROVIDER_SCHEMA};
use rustid_core::admin::{AdminError, EntityId, SaveResult, Saved, Versioned};
use rustid_core::options::TimeSpan;
use rustid_core::stores::{
    ConfigurationStore, CreateOutcome, EntityKind, StoreError, StoredEntity, UpdateOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::model::{
    Binding, Endpoint, IndexedEndpoint, KeyUse, ServiceProvider, SigningBehavior, SpCertificate,
};

const KIND: EntityKind = EntityKind::SamlServiceProvider;
const NAME: &str = "samlServiceProvider";

/// A service provider endpoint: its binding and location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointConfiguration {
    #[serde(default)]
    pub location: String,
    #[serde(default = "redirect")]
    pub binding: Binding,
}

/// An indexed service provider endpoint (an assertion consumer service).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndexedEndpointConfiguration {
    #[serde(default)]
    pub location: String,
    #[serde(default = "redirect")]
    pub binding: Binding,
    #[serde(default)]
    pub index: i32,
    #[serde(default)]
    pub is_default: bool,
}

/// The default for an unset binding (0).
fn redirect() -> Binding {
    Binding::HttpRedirect
}

/// An unset id is a new certificate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CertificateInput {
    #[serde(default)]
    pub id: Option<EntityId>,
    #[serde(default)]
    pub base64_data: String,
    #[serde(default, rename = "use")]
    pub key_use: KeyUse,
}

/// The certificate and, read from it, its
/// subject, thumbprint and expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateConfiguration {
    pub id: EntityId,
    pub base64_data: String,
    #[serde(rename = "use")]
    pub key_use: KeyUse,
    pub subject: Option<String>,
    pub thumbprint: Option<String>,
    pub not_after: Option<DateTime<Utc>>,
}

fn unspecified() -> Option<String> {
    Some(crate::constants::NAME_ID_UNSPECIFIED.to_owned())
}

fn yes() -> bool {
    true
}

/// The create saml service provider / the update SAML service provider. List entries
/// may be null, which the structure checks refuse.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SamlServiceProviderInput {
    #[serde(default)]
    pub entity_id: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub clock_skew: Option<TimeSpan>,
    #[serde(default)]
    pub request_max_age: Option<TimeSpan>,
    #[serde(default)]
    pub assertion_lifetime: Option<TimeSpan>,
    #[serde(default)]
    pub assertion_consumer_service_urls: Vec<Option<IndexedEndpointConfiguration>>,
    #[serde(default)]
    pub single_logout_service_urls: Vec<Option<EndpointConfiguration>>,
    #[serde(default)]
    pub require_signed_authn_requests: Option<bool>,
    #[serde(default)]
    pub require_signed_logout_responses: Option<bool>,
    #[serde(default)]
    pub certificates: Vec<Option<CertificateInput>>,
    #[serde(default)]
    pub allow_idp_initiated: bool,
    #[serde(default)]
    pub allowed_scopes: Vec<Option<String>>,
    #[serde(default)]
    pub claim_mappings: BTreeMap<String, String>,
    #[serde(default)]
    pub authn_context_mappings: BTreeMap<String, String>,
    #[serde(default)]
    pub requested_claim_types: Vec<String>,
    #[serde(default = "unspecified")]
    pub default_name_id_format: Option<String>,
    #[serde(default)]
    pub email_name_id_claim_type: Option<String>,
    #[serde(default)]
    pub signing_behavior: Option<SigningBehavior>,
    #[serde(default)]
    pub allowed_signature_algorithms: Vec<String>,
    #[serde(default)]
    pub extended_properties: Map<String, Value>,
}

/// Members a read returns that an update ignores.
const READ_ONLY: [&str; 2] = ["id", "version"];
/// Lists and maps where `null` means empty.
const COLLECTIONS: [&str; 9] = [
    "assertionConsumerServiceUrls",
    "singleLogoutServiceUrls",
    "certificates",
    "allowedScopes",
    "claimMappings",
    "authnContextMappings",
    "requestedClaimTypes",
    "allowedSignatureAlgorithms",
    "extendedProperties",
];

impl SamlServiceProviderInput {
    /// The input from a request body (a read's body works as an update:
    /// `id`, `version` and the certificates' read-only members are ignored).
    pub fn from_json(body: Value) -> Result<Self, AdminError> {
        let Value::Object(mut body) = body else {
            return Err(AdminError::validation_failed(
                "The request body must be a JSON object.",
            ));
        };
        for key in READ_ONLY {
            body.remove(key);
        }
        body.retain(|key, value| !(value.is_null() && COLLECTIONS.contains(&key.as_str())));
        if let Some(Value::Array(certificates)) = body.get_mut("certificates") {
            for certificate in certificates.iter_mut().filter_map(Value::as_object_mut) {
                for key in ["subject", "thumbprint", "notAfter"] {
                    certificate.remove(key);
                }
                if certificate.get("id").and_then(Value::as_str) == Some(NIL) {
                    certificate.remove("id");
                }
            }
        }
        serde_json::from_value(Value::Object(body)).map_err(|e| {
            let message = e.to_string();
            match message
                .strip_prefix("unknown field `")
                .and_then(|rest| rest.split('`').next())
            {
                Some(field) => AdminError::invalid_value(
                    field,
                    format!("'{field}' is not a SAML service provider setting."),
                ),
                None => AdminError::validation_failed(format!(
                    "Invalid SAML service provider: {message}"
                )),
            }
        })
    }
}

/// The nil UUID, which clients send for a new certificate.
const NIL: &str = "00000000-0000-0000-0000-000000000000";

/// `SamlServiceProviderConfiguration`.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlServiceProviderConfiguration {
    pub entity_id: String,
    pub enabled: bool,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub clock_skew: Option<TimeSpan>,
    pub request_max_age: Option<TimeSpan>,
    pub assertion_lifetime: Option<TimeSpan>,
    pub assertion_consumer_service_urls: Vec<IndexedEndpointConfiguration>,
    pub single_logout_service_urls: Vec<EndpointConfiguration>,
    pub require_signed_authn_requests: Option<bool>,
    pub require_signed_logout_responses: Option<bool>,
    pub certificates: Vec<CertificateConfiguration>,
    pub allow_idp_initiated: bool,
    pub allowed_scopes: Vec<String>,
    pub claim_mappings: BTreeMap<String, String>,
    pub authn_context_mappings: BTreeMap<String, String>,
    pub requested_claim_types: Vec<String>,
    pub default_name_id_format: Option<String>,
    pub email_name_id_claim_type: Option<String>,
    pub signing_behavior: Option<SigningBehavior>,
    pub allowed_signature_algorithms: Vec<String>,
    pub extended_properties: Map<String, Value>,
}

/// `SamlServiceProviderFilter`: entity id and display name substrings, and
/// enabled or not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SamlServiceProviderFilter {
    pub entity_id: Option<String>,
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
}

/// `SamlServiceProviderSortField`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamlServiceProviderSortField {
    EntityId,
    DisplayName,
    Enabled,
}

/// `SamlServiceProviderListItem`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SamlServiceProviderListItem {
    pub id: EntityId,
    pub entity_id: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub description: Option<String>,
    pub certificate_count: usize,
    pub allowed_scope_count: usize,
}

/// The input after the structure checks: the runtime model, its
/// certificates' ids (`None`: new), and the extended properties.
struct Checked {
    sp: ServiceProvider,
    certificate_ids: Vec<Option<EntityId>>,
    extended_properties: Map<String, Value>,
}

fn invalid(property: &str, message: impl Into<String>) -> AdminError {
    AdminError::invalid_value(property, message)
}

fn blank(text: &str) -> bool {
    text.trim().is_empty()
}

/// `Uri.TryCreate(…, UriKind.Absolute)`.
fn absolute(location: &str) -> bool {
    crate::xml::traverser::is_absolute_uri(location)
}

/// The DER certificate in `base64` (whitespace ignored), checked to parse
/// as X.509 and cut to the
/// certificate itself.
fn certificate_der(base64: &str) -> Result<Vec<u8>, AdminError> {
    let compact: String = base64.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = STANDARD.decode(compact).map_err(|_| {
        invalid(
            "Certificates",
            "Certificate Base64Data is not valid base64.",
        )
    })?;
    use x509_parser::prelude::FromDer;
    let (rest, _) = x509_parser::certificate::X509Certificate::from_der(&bytes).map_err(|_| {
        invalid(
            "Certificates",
            "Certificate Base64Data does not contain a valid X.509 certificate.",
        )
    })?;
    let used = bytes.len() - rest.len();
    Ok(bytes[..used].to_vec())
}

/// The structure checks, in a fixed order with fixed words.
fn structure(input: SamlServiceProviderInput) -> Result<Checked, AdminError> {
    if blank(&input.entity_id) {
        return Err(AdminError::required("EntityId"));
    }
    if input.display_name.as_deref().is_some_and(blank) {
        return Err(invalid(
            "DisplayName",
            "Display name must not be empty or whitespace.",
        ));
    }
    const ACS: &str = "AssertionConsumerServiceUrls";
    let mut acs = Vec::new();
    for endpoint in input.assertion_consumer_service_urls {
        let Some(endpoint) = endpoint else {
            return Err(invalid(
                ACS,
                "ACS endpoint list must not contain null entries.",
            ));
        };
        if blank(&endpoint.location) {
            return Err(invalid(ACS, "ACS endpoint location must not be empty."));
        }
        if !absolute(&endpoint.location) {
            return Err(invalid(
                ACS,
                format!(
                    "ACS endpoint location '{}' is not a valid absolute URI.",
                    endpoint.location
                ),
            ));
        }
        acs.push(endpoint);
    }
    let mut indices = HashSet::new();
    if !acs.iter().all(|a| indices.insert(a.index)) {
        return Err(invalid(
            ACS,
            "ACS endpoint list contains duplicate Index values.",
        ));
    }
    const SLO: &str = "SingleLogoutServiceUrls";
    let mut slo = Vec::new();
    for endpoint in input.single_logout_service_urls {
        let Some(endpoint) = endpoint else {
            return Err(invalid(
                SLO,
                "SLO endpoint list must not contain null entries.",
            ));
        };
        if blank(&endpoint.location) {
            return Err(invalid(SLO, "SLO endpoint location must not be empty."));
        }
        if !absolute(&endpoint.location) {
            return Err(invalid(
                SLO,
                format!(
                    "SLO endpoint location '{}' is not a valid absolute URI.",
                    endpoint.location
                ),
            ));
        }
        slo.push(endpoint);
    }
    let mut certificates = Vec::new();
    let mut certificate_ids = Vec::new();
    for certificate in input.certificates {
        let Some(certificate) = certificate else {
            return Err(invalid(
                "Certificates",
                "Certificate list must not contain null entries.",
            ));
        };
        if blank(&certificate.base64_data) {
            return Err(invalid(
                "Certificates",
                "Certificate Base64Data must not be empty.",
            ));
        }
        certificates.push(SpCertificate {
            der: certificate_der(&certificate.base64_data)?,
            key_use: certificate.key_use,
        });
        certificate_ids.push(certificate.id);
    }
    let mut ids = HashSet::new();
    if !certificate_ids.iter().flatten().all(|id| ids.insert(*id)) {
        return Err(invalid(
            "Certificates",
            "Certificate list contains duplicate IDs.",
        ));
    }
    let mut allowed_scopes = Vec::new();
    for scope in input.allowed_scopes {
        match scope {
            Some(scope) if !blank(&scope) => allowed_scopes.push(scope),
            _ => {
                return Err(invalid(
                    "AllowedScopes",
                    "Scope must not be null or whitespace.",
                ));
            }
        }
    }
    let sp = ServiceProvider {
        entity_id: input.entity_id,
        display_name: input.display_name,
        description: input.description,
        enabled: input.enabled,
        clock_skew: input.clock_skew,
        request_max_age: input.request_max_age,
        assertion_lifetime: input.assertion_lifetime,
        assertion_consumer_service_urls: acs
            .into_iter()
            .map(|a| IndexedEndpoint {
                location: a.location,
                binding: a.binding,
                index: a.index,
                is_default: a.is_default,
            })
            .collect(),
        single_logout_service_urls: slo
            .into_iter()
            .map(|s| Endpoint {
                location: s.location,
                binding: s.binding,
            })
            .collect(),
        require_signed_authn_requests: input.require_signed_authn_requests,
        require_signed_logout_responses: input.require_signed_logout_responses,
        certificates,
        allow_idp_initiated: input.allow_idp_initiated,
        allowed_scopes,
        claim_mappings: input.claim_mappings,
        authn_context_mappings: input.authn_context_mappings,
        requested_claim_types: input.requested_claim_types,
        default_name_id_format: input.default_name_id_format,
        email_name_id_claim_type: input.email_name_id_claim_type,
        signing_behavior: input.signing_behavior,
        // The runtime store maps an empty list to none (the defaults).
        allowed_signature_algorithms: (!input.allowed_signature_algorithms.is_empty())
            .then_some(input.allowed_signature_algorithms),
    };
    Ok(Checked {
        sp,
        certificate_ids,
        extended_properties: input.extended_properties,
    })
}

/// The stored data: the runtime model, certificate ids, extended properties.
fn data(sp: &ServiceProvider, ids: &[EntityId], extended_properties: &Map<String, Value>) -> Value {
    let mut json = serde_json::to_value(sp).expect("a service provider serialises");
    if let Some(Value::Array(certificates)) = json.get_mut("certificates") {
        for (certificate, id) in certificates.iter_mut().zip(ids) {
            if let Value::Object(object) = certificate {
                object.insert("id".into(), serde_json::to_value(id).expect("an id"));
            }
        }
    }
    if let Value::Object(object) = &mut json {
        object.insert(
            "extendedProperties".into(),
            Value::Object(extended_properties.clone()),
        );
    }
    json
}

fn parse(entity: &StoredEntity) -> Result<ServiceProvider, StoreError> {
    serde_json::from_value(entity.data.clone())
        .map_err(|e| StoreError::Backend(format!("stored {}: {e}", entity.key)))
}

/// The stored certificates' ids, in order; a certificate stored without one
/// (imported from a file) gets one derived from its position and the entity.
fn stored_certificate_ids(entity: &StoredEntity) -> Vec<EntityId> {
    entity
        .data
        .get("certificates")
        .and_then(Value::as_array)
        .map(|certificates| {
            certificates
                .iter()
                .enumerate()
                .map(|(index, c)| {
                    c.get("id")
                        .and_then(|id| serde_json::from_value(id.clone()).ok())
                        .unwrap_or_else(|| derived_id(&entity.id, index))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A stable id for the `index`th certificate of an entity stored without
/// certificate ids.
fn derived_id(entity: &EntityId, index: usize) -> EntityId {
    let digest = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        format!("{entity}/certificate/{index}").as_bytes(),
    );
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_ref()[..16]);
    bytes[6] = 0x70 | (bytes[6] & 0x0f);
    bytes[8] = 0x80 | (bytes[8] & 0x3f);
    EntityId(bytes)
}

/// A distinguished name's text: the RDNs last to first.
fn subject(certificate: &x509_parser::certificate::X509Certificate<'_>) -> String {
    let registry = x509_parser::objects::oid_registry();
    let rdns: Vec<String> = certificate
        .subject()
        .iter()
        .map(|rdn| {
            rdn.iter()
                .map(|attribute| {
                    let name = x509_parser::objects::oid2abbrev(attribute.attr_type(), registry)
                        .map(str::to_owned)
                        .unwrap_or_else(|_| format!("OID.{}", attribute.attr_type()));
                    let value = attribute
                        .as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|_| format!("{:?}", attribute.attr_value().data));
                    format!("{name}={value}")
                })
                .collect::<Vec<_>>()
                .join(" + ")
        })
        .collect();
    rdns.into_iter().rev().collect::<Vec<_>>().join(", ")
}

fn certificate_configuration(
    id: EntityId,
    certificate: &SpCertificate,
) -> CertificateConfiguration {
    use x509_parser::prelude::FromDer;
    let parsed = x509_parser::certificate::X509Certificate::from_der(&certificate.der)
        .ok()
        .map(|(_, c)| c);
    let thumbprint = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY,
        &certificate.der,
    )
    .as_ref()
    .iter()
    .map(|b| format!("{b:02X}"))
    .collect();
    CertificateConfiguration {
        id,
        base64_data: STANDARD.encode(&certificate.der),
        key_use: certificate.key_use,
        subject: parsed.as_ref().map(subject),
        thumbprint: Some(thumbprint),
        not_after: parsed
            .as_ref()
            .and_then(|c| DateTime::from_timestamp(c.validity().not_after.timestamp(), 0)),
    }
}

fn configuration(
    sp: ServiceProvider,
    ids: &[EntityId],
    extended_properties: Map<String, Value>,
) -> SamlServiceProviderConfiguration {
    SamlServiceProviderConfiguration {
        certificates: sp
            .certificates
            .iter()
            .zip(ids)
            .map(|(c, id)| certificate_configuration(*id, c))
            .collect(),
        entity_id: sp.entity_id,
        enabled: sp.enabled,
        display_name: sp.display_name,
        description: sp.description,
        clock_skew: sp.clock_skew,
        request_max_age: sp.request_max_age,
        assertion_lifetime: sp.assertion_lifetime,
        assertion_consumer_service_urls: sp
            .assertion_consumer_service_urls
            .into_iter()
            .map(|a| IndexedEndpointConfiguration {
                location: a.location,
                binding: a.binding,
                index: a.index,
                is_default: a.is_default,
            })
            .collect(),
        single_logout_service_urls: sp
            .single_logout_service_urls
            .into_iter()
            .map(|s| EndpointConfiguration {
                location: s.location,
                binding: s.binding,
            })
            .collect(),
        require_signed_authn_requests: sp.require_signed_authn_requests,
        require_signed_logout_responses: sp.require_signed_logout_responses,
        allow_idp_initiated: sp.allow_idp_initiated,
        allowed_scopes: sp.allowed_scopes,
        claim_mappings: sp.claim_mappings,
        authn_context_mappings: sp.authn_context_mappings,
        requested_claim_types: sp.requested_claim_types,
        default_name_id_format: sp.default_name_id_format,
        email_name_id_claim_type: sp.email_name_id_claim_type,
        signing_behavior: sp.signing_behavior,
        allowed_signature_algorithms: sp.allowed_signature_algorithms.unwrap_or_default(),
        extended_properties,
    }
}

/// `SamlServiceProviderAdmin`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SamlServiceProviderAdmin;

impl SamlServiceProviderAdmin {
    /// The configuration validator, then the extended properties.
    async fn validate(
        store: &dyn ConfigurationStore,
        checked: &Checked,
    ) -> Result<Option<AdminError>, StoreError> {
        if let Err(message) = crate::validation::validate_service_provider(&checked.sp) {
            return Ok(Some(AdminError::validation_failed(message)));
        }
        Ok(schemas::check_extended_properties(
            store,
            SAML_SERVICE_PROVIDER_SCHEMA,
            &checked.extended_properties,
        )
        .await?
        .err())
    }

    pub async fn create(
        &self,
        store: &dyn ConfigurationStore,
        input: SamlServiceProviderInput,
    ) -> SaveResult {
        let checked = match structure(input) {
            Ok(checked) => checked,
            Err(error) => return Ok(Err(vec![error])),
        };
        if let Some(error) = Self::validate(store, &checked).await? {
            return Ok(Err(vec![error]));
        }
        // Every certificate gets a new id on create.
        let ids: Vec<EntityId> = checked
            .certificate_ids
            .iter()
            .map(|_| EntityId::new_v7())
            .collect();
        let entity = StoredEntity {
            id: EntityId::new_v7(),
            key: checked.sp.entity_id.clone(),
            version: 1,
            data: data(&checked.sp, &ids, &checked.extended_properties),
        };
        Ok(match store.create(KIND, &entity).await? {
            CreateOutcome::Created => Ok(Saved {
                id: entity.id,
                version: 1,
            }),
            CreateOutcome::KeyExists => Err(vec![AdminError::already_exists(
                NAME,
                &checked.sp.entity_id,
            )]),
        })
    }

    async fn versioned(
        store: &dyn ConfigurationStore,
        entity: Option<StoredEntity>,
    ) -> Result<Option<Versioned<SamlServiceProviderConfiguration>>, StoreError> {
        let Some(entity) = entity else {
            return Ok(None);
        };
        let sp = parse(&entity)?;
        let extended_properties = schemas::readable_extended_properties(
            store,
            SAML_SERVICE_PROVIDER_SCHEMA,
            schemas::stored_extended_properties(&entity.data),
        )
        .await?;
        Ok(Some(Versioned {
            id: entity.id,
            version: entity.version,
            item: configuration(sp, &stored_certificate_ids(&entity), extended_properties),
        }))
    }

    pub async fn get(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
    ) -> Result<Option<Versioned<SamlServiceProviderConfiguration>>, StoreError> {
        Self::versioned(store, store.read(KIND, id).await?).await
    }

    pub async fn get_by_entity_id(
        &self,
        store: &dyn ConfigurationStore,
        entity_id: &str,
    ) -> Result<Option<Versioned<SamlServiceProviderConfiguration>>, StoreError> {
        Self::versioned(store, store.read_by_key(KIND, entity_id).await?).await
    }

    /// Replaces the provider; certificates sent with an id keep it, others
    /// get a new one.
    pub async fn update(
        &self,
        store: &dyn ConfigurationStore,
        id: &EntityId,
        input: SamlServiceProviderInput,
        expected_version: i32,
    ) -> SaveResult {
        let checked = match structure(input) {
            Ok(checked) => checked,
            Err(error) => return Ok(Err(vec![error])),
        };
        if store.read(KIND, id).await?.is_none() {
            return Ok(Err(vec![AdminError::not_found(NAME, &id.to_string())]));
        }
        if let Some(error) = Self::validate(store, &checked).await? {
            return Ok(Err(vec![error]));
        }
        let ids: Vec<EntityId> = checked
            .certificate_ids
            .iter()
            .map(|id| id.unwrap_or_else(EntityId::new_v7))
            .collect();
        let entity = StoredEntity {
            id: *id,
            key: checked.sp.entity_id.clone(),
            version: expected_version,
            data: data(&checked.sp, &ids, &checked.extended_properties),
        };
        Ok(match store.update(KIND, &entity).await? {
            UpdateOutcome::Updated => Ok(Saved {
                id: *id,
                version: expected_version + 1,
            }),
            UpdateOutcome::UnexpectedVersion => Err(vec![AdminError::version_conflict()]),
            UpdateOutcome::DoesNotExist => Err(vec![AdminError::not_found(NAME, &id.to_string())]),
            UpdateOutcome::KeyConflict => Err(vec![AdminError::already_exists(
                NAME,
                &checked.sp.entity_id,
            )]),
        })
    }

    /// Idempotent: version 0.
    pub async fn delete(&self, store: &dyn ConfigurationStore, id: &EntityId) -> SaveResult {
        store.delete(KIND, id).await?;
        Ok(Ok(Saved {
            id: *id,
            version: 0,
        }))
    }

    pub async fn query(
        &self,
        store: &dyn ConfigurationStore,
        filter: &SamlServiceProviderFilter,
        sort: Option<(SamlServiceProviderSortField, Direction)>,
        range: &Range,
    ) -> Result<Result<QueryResult<SamlServiceProviderListItem>, AdminError>, StoreError> {
        let contains = |value: Option<&str>, part: &Option<String>| {
            part.as_deref()
                .is_none_or(|part| value.is_some_and(|v| v.contains(part)))
        };
        let mut items = Vec::new();
        for entity in store.list(KIND).await? {
            let sp = parse(&entity)?;
            if contains(Some(&sp.entity_id), &filter.entity_id)
                && contains(sp.display_name.as_deref(), &filter.display_name)
                && filter.enabled.is_none_or(|e| sp.enabled == e)
            {
                items.push(SamlServiceProviderListItem {
                    id: entity.id,
                    certificate_count: sp.certificates.len(),
                    allowed_scope_count: sp.allowed_scopes.len(),
                    entity_id: sp.entity_id,
                    display_name: sp.display_name,
                    enabled: sp.enabled,
                    description: sp.description,
                });
            }
        }
        let (field, direction) =
            sort.unwrap_or((SamlServiceProviderSortField::EntityId, Direction::Ascending));
        items.sort_by(|a, b| {
            let order = match field {
                SamlServiceProviderSortField::EntityId => a.entity_id.cmp(&b.entity_id),
                SamlServiceProviderSortField::DisplayName => a.display_name.cmp(&b.display_name),
                SamlServiceProviderSortField::Enabled => a.enabled.cmp(&b.enabled),
            };
            let order = match direction {
                Direction::Ascending => order,
                Direction::Descending => order.reverse(),
            };
            order.then_with(|| a.id.cmp(&b.id))
        });
        Ok(paginate(items, range))
    }
}
