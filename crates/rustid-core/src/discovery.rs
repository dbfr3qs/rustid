//! Discovery and JWKS documents, with their entries in a fixed order.

use serde_json::{Map, Value, json};

use crate::keys::LoadedKey;
use crate::options::{ProtocolOptions, RegistrationEndpointMode};
use crate::resources::Resources;

pub const DISCOVERY_PATH: &str = ".well-known/openid-configuration";
pub const JWKS_PATH: &str = ".well-known/openid-configuration/jwks";
pub const OAUTH_METADATA_PATH: &str = ".well-known/oauth-authorization-server";

/// The response types discovery advertises.
pub const RESPONSE_TYPES: &[&str] = &[
    "code",
    "token",
    "id_token",
    "id_token token",
    "code id_token",
    "code token",
    "code id_token token",
];
/// The response modes discovery advertises.
pub const RESPONSE_MODES: &[&str] = &["form_post", "query", "fragment"];

/// Capabilities that come from registered services rather than from
/// options. Until the hooks and client authentication that own them exist,
/// these are configured placeholders (see the roadmap, Phase 1).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DiscoveryFeatures {
    /// A password grant validator is registered (`password` grant advertised).
    pub password_grant: bool,
    /// Extension grant types, in registration order.
    pub extension_grants: Vec<String>,
    /// `private_key_jwt` client authentication is enabled.
    pub private_key_jwt: bool,
}

impl DiscoveryFeatures {
    /// The secrets list parser, in parser
    /// registration order.
    pub fn auth_methods(&self) -> Vec<String> {
        let mut methods = vec![
            "client_secret_basic".to_owned(),
            "client_secret_post".to_owned(),
        ];
        if self.private_key_jwt {
            methods.push("private_key_jwt".to_owned());
        }
        methods
    }
}

pub struct DiscoveryContext<'a> {
    pub options: &'a ProtocolOptions,
    pub resources: &'a Resources,
    /// Whether any validation key exists (the key set is non-empty).
    pub has_validation_keys: bool,
    /// Algorithms of the signing keys, in order.
    pub signing_algorithms: &'a [String],
    pub features: &'a DiscoveryFeatures,
    /// Origin plus path base, without a trailing slash.
    pub base_url: &'a str,
    pub issuer: &'a str,
}

fn strings(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn strs(values: &[&str]) -> Value {
    Value::Array(
        values
            .iter()
            .map(|v| Value::String((*v).to_owned()))
            .collect(),
    )
}

pub fn discovery_document(ctx: &DiscoveryContext<'_>) -> Map<String, Value> {
    let o = ctx.options;
    let e = &o.endpoints;
    let d = &o.discovery;
    let base = format!("{}/", ctx.base_url.trim_end_matches('/'));
    let url = |path: &str| Value::String(format!("{base}{path}"));
    let mut m = Map::new();

    m.insert("issuer".into(), Value::String(ctx.issuer.to_owned()));

    if d.show_key_set && ctx.has_validation_keys {
        m.insert("jwks_uri".into(), url(JWKS_PATH));
    }

    if d.show_endpoints {
        let endpoints: [(bool, &str, &str); 9] = [
            (
                e.enable_authorize_endpoint,
                "authorization_endpoint",
                "connect/authorize",
            ),
            (e.enable_token_endpoint, "token_endpoint", "connect/token"),
            (
                e.enable_user_info_endpoint,
                "userinfo_endpoint",
                "connect/userinfo",
            ),
            (
                e.enable_end_session_endpoint,
                "end_session_endpoint",
                "connect/endsession",
            ),
            (
                e.enable_check_session_endpoint,
                "check_session_iframe",
                "connect/checksession",
            ),
            (
                e.enable_token_revocation_endpoint,
                "revocation_endpoint",
                "connect/revocation",
            ),
            (
                e.enable_introspection_endpoint,
                "introspection_endpoint",
                "connect/introspect",
            ),
            (
                e.enable_device_authorization_endpoint,
                "device_authorization_endpoint",
                "connect/deviceauthorization",
            ),
            (
                e.enable_backchannel_authentication_endpoint,
                "backchannel_authentication_endpoint",
                "connect/ciba",
            ),
        ];
        for (enabled, key, path) in endpoints {
            if enabled {
                m.insert(key.into(), url(path));
            }
        }
        if e.enable_pushed_authorization_endpoint {
            m.insert(
                "pushed_authorization_request_endpoint".into(),
                url("connect/par"),
            );
            m.insert(
                "require_pushed_authorization_requests".into(),
                Value::Bool(o.pushed_authorization.required),
            );
        }
        if o.mutual_tls.enabled {
            let aliases: Map<String, Value> = [
                (e.enable_token_endpoint, "token_endpoint", "connect/token"),
                (
                    e.enable_token_revocation_endpoint,
                    "revocation_endpoint",
                    "connect/revocation",
                ),
                (
                    e.enable_introspection_endpoint,
                    "introspection_endpoint",
                    "connect/introspect",
                ),
                (
                    e.enable_device_authorization_endpoint,
                    "device_authorization_endpoint",
                    "connect/deviceauthorization",
                ),
                (
                    e.enable_pushed_authorization_endpoint,
                    "pushed_authorization_request_endpoint",
                    "connect/par",
                ),
            ]
            .into_iter()
            .filter(|(enabled, _, _)| *enabled)
            .map(|(_, key, path)| {
                let alias =
                    crate::client_certificate::mtls_endpoint(&o.mutual_tls, ctx.base_url, path);
                (key.to_owned(), Value::String(alias))
            })
            .collect();
            if !aliases.is_empty() {
                m.insert("mtls_endpoint_aliases".into(), Value::Object(aliases));
            }
        }
    }

    if e.enable_end_session_endpoint {
        for key in [
            "frontchannel_logout_supported",
            "frontchannel_logout_session_supported",
            "backchannel_logout_supported",
            "backchannel_logout_session_supported",
        ] {
            m.insert(key.into(), Value::Bool(true));
        }
    }

    if d.show_identity_scopes || d.show_api_scopes || d.show_claims {
        let resources = ctx.resources.enabled();
        let mut scopes: Vec<String> = Vec::new();
        if d.show_identity_scopes {
            scopes.extend(
                resources
                    .identity_resources
                    .iter()
                    .filter(|r| r.show_in_discovery_document)
                    .map(|r| r.name.clone()),
            );
        }
        if d.show_api_scopes {
            scopes.extend(
                resources
                    .api_scopes
                    .iter()
                    .filter(|r| r.show_in_discovery_document)
                    .map(|r| r.name.clone()),
            );
            scopes.push("offline_access".into());
        }
        if !scopes.is_empty() {
            m.insert("scopes_supported".into(), strings(&scopes));
        }
        if d.show_claims {
            let mut claims: Vec<String> = Vec::new();
            let all = resources
                .identity_resources
                .iter()
                .filter(|r| r.show_in_discovery_document)
                .flat_map(|r| &r.user_claims)
                .chain(
                    resources
                        .api_resources
                        .iter()
                        .filter(|r| r.show_in_discovery_document)
                        .flat_map(|r| &r.user_claims),
                )
                .chain(
                    resources
                        .api_scopes
                        .iter()
                        .filter(|r| r.show_in_discovery_document)
                        .flat_map(|r| &r.user_claims),
                );
            for claim in all {
                if !claims.contains(claim) {
                    claims.push(claim.clone());
                }
            }
            m.insert("claims_supported".into(), strings(&claims));
        }
    }

    if d.show_grant_types {
        let mut grants: Vec<String> = [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "implicit",
        ]
        .iter()
        .map(|g| (*g).to_owned())
        .collect();
        if ctx.features.password_grant {
            grants.push("password".into());
        }
        if e.enable_device_authorization_endpoint {
            grants.push("urn:ietf:params:oauth:grant-type:device_code".into());
        }
        if e.enable_backchannel_authentication_endpoint {
            grants.push("urn:openid:params:grant-type:ciba".into());
        }
        if d.show_extension_grant_types {
            grants.extend(ctx.features.extension_grants.iter().cloned());
        }
        m.insert("grant_types_supported".into(), strings(&grants));
    }

    if d.show_response_types {
        m.insert("response_types_supported".into(), strs(RESPONSE_TYPES));
    }
    if d.show_response_modes {
        let mut modes = RESPONSE_MODES.to_vec();
        if o.jarm.enabled {
            modes.extend_from_slice(crate::authorize::jarm::JARM_RESPONSE_MODES);
        }
        m.insert("response_modes_supported".into(), strs(&modes));
    }

    // The parsers' methods, then mTLS's.
    let mut methods = ctx.features.auth_methods();
    if o.mutual_tls.enabled {
        methods.push("tls_client_auth".to_owned());
        methods.push("self_signed_tls_client_auth".to_owned());
    }
    let with_private_key_jwt = methods.iter().any(|m| m == "private_key_jwt")
        && !o.supported_client_assertion_signing_algorithms.is_empty();
    let auth_sections = [
        (
            d.show_token_endpoint_authentication_methods,
            "token_endpoint_auth_methods_supported",
            "token_endpoint_auth_signing_alg_values_supported",
        ),
        (
            d.show_revocation_endpoint_authentication_methods,
            "revocation_endpoint_auth_methods_supported",
            "revocation_endpoint_auth_signing_alg_values_supported",
        ),
        (
            d.show_introspection_endpoint_authentication_methods,
            "introspection_endpoint_auth_methods_supported",
            "introspection_endpoint_auth_signing_alg_values_supported",
        ),
    ];
    for (show, methods_key, algs_key) in auth_sections {
        if show {
            m.insert(methods_key.into(), strings(&methods));
            if with_private_key_jwt {
                m.insert(
                    algs_key.into(),
                    strings(&o.supported_client_assertion_signing_algorithms),
                );
            }
        }
    }

    let signing = ctx.signing_algorithms.to_vec();
    if !signing.is_empty() {
        m.insert(
            "id_token_signing_alg_values_supported".into(),
            strings(&signing),
        );
        // JARM signs with the same keys (encryption isn't offered).
        if o.jarm.enabled {
            m.insert(
                "authorization_signing_alg_values_supported".into(),
                strings(&signing),
            );
        }
        if e.enable_user_info_endpoint {
            m.insert(
                "userinfo_signing_alg_values_supported".into(),
                strings(&signing),
            );
        }
        if e.enable_introspection_endpoint {
            m.insert(
                "introspection_signing_alg_values_supported".into(),
                strings(&signing),
            );
        }
    }

    m.insert("subject_types_supported".into(), strs(&["public"]));
    m.insert(
        "code_challenge_methods_supported".into(),
        strs(&["plain", "S256"]),
    );

    if e.enable_authorize_endpoint {
        m.insert("request_parameter_supported".into(), Value::Bool(true));
        if !o.supported_request_object_signing_algorithms.is_empty() {
            m.insert(
                "request_object_signing_alg_values_supported".into(),
                strings(&o.supported_request_object_signing_algorithms),
            );
        }
        if e.enable_jwt_request_uri {
            m.insert("request_uri_parameter_supported".into(), Value::Bool(true));
        }
        if !o.user_interaction.prompt_values_supported.is_empty() {
            m.insert(
                "prompt_values_supported".into(),
                strings(&o.user_interaction.prompt_values_supported),
            );
        }
    }

    m.insert(
        "authorization_response_iss_parameter_supported".into(),
        Value::Bool(o.emit_issuer_identification_response_parameter),
    );

    if o.mutual_tls.enabled {
        m.insert(
            "tls_client_certificate_bound_access_tokens".into(),
            Value::Bool(true),
        );
    }

    if e.enable_backchannel_authentication_endpoint {
        m.insert(
            "backchannel_token_delivery_modes_supported".into(),
            strs(&["poll"]),
        );
        m.insert(
            "backchannel_user_code_parameter_supported".into(),
            Value::Bool(true),
        );
        if !o.supported_request_object_signing_algorithms.is_empty() {
            m.insert(
                "backchannel_authentication_request_signing_alg_values_supported".into(),
                strings(&o.supported_request_object_signing_algorithms),
            );
        }
    }

    if e.enable_token_endpoint && !o.dpop.supported_dpop_signing_algorithms.is_empty() {
        m.insert(
            "dpop_signing_alg_values_supported".into(),
            strings(&o.dpop.supported_dpop_signing_algorithms),
        );
    }

    let registration = &d.dynamic_client_registration;
    match registration.registration_endpoint_mode {
        RegistrationEndpointMode::Static => {
            if let Some(endpoint) = &registration.static_registration_endpoint {
                m.insert(
                    "registration_endpoint".into(),
                    Value::String(endpoint.clone()),
                );
            }
        }
        RegistrationEndpointMode::Inferred => {
            m.insert("registration_endpoint".into(), url("connect/dcr"));
        }
        RegistrationEndpointMode::None => {}
    }

    for (key, value) in &d.custom_entries {
        if m.contains_key(key) {
            continue; // logged; the standard entry stays
        }
        let value = match value {
            Value::String(s)
                if d.expand_relative_paths_in_custom_entries && s.starts_with("~/") =>
            {
                Value::String(format!("{base}{}", &s[2..]))
            }
            other => other.clone(),
        };
        m.insert(key.clone(), value);
    }

    m
}

pub fn jwks_document(keys: &[std::sync::Arc<LoadedKey>]) -> Value {
    json!({ "keys": keys.iter().map(|k| &k.jwk).collect::<Vec<_>>() })
}
