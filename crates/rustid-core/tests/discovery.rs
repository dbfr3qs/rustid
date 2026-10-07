use std::path::{Path, PathBuf};

use rustid_core::discovery::{
    DiscoveryContext, DiscoveryFeatures, discovery_document, jwks_document,
};
use rustid_core::keys::{KeyConfig, KeyMaterial};
use rustid_core::options::ProtocolOptions;
use rustid_core::resources::Resources;
use serde_json::{Value, json};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture_keys() -> KeyMaterial {
    let key = KeyConfig {
        kid: "fixture-rsa-1".into(),
        alg: "RS256".into(),
        key_file: root().join("fixtures/signing-key.pem"),
        cert_file: None,
    };
    KeyMaterial::load(&[key], &[]).unwrap()
}

fn fixture_resources() -> Resources {
    Resources::load(&root().join("fixtures/resources.json")).unwrap()
}

/// The test feature set: a password grant is registered.
fn reference_features() -> DiscoveryFeatures {
    DiscoveryFeatures {
        password_grant: true,
        ..Default::default()
    }
}

fn doc(options: &ProtocolOptions, keys: &KeyMaterial, features: &DiscoveryFeatures) -> Value {
    let resources = fixture_resources();
    let algorithms = keys.signing_algorithms();
    let ctx = DiscoveryContext {
        options,
        resources: &resources,
        has_validation_keys: keys.validation_keys().next().is_some(),
        signing_algorithms: &algorithms,
        features,
        base_url: "{base}",
        issuer: "https://idsrv.test",
    };
    Value::Object(discovery_document(&ctx))
}

/// The expected document, in `tests/expected/` (`{base}` stands for the
/// server's base URL).
fn recorded(name: &str) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/expected")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn default_document_equals_the_recorded_reference_document() {
    let options = ProtocolOptions {
        issuer_uri: Some("https://idsrv.test".into()),
        ..Default::default()
    };
    assert_eq!(
        doc(&options, &fixture_keys(), &reference_features()),
        recorded("discovery-document.json")
    );
}

#[test]
fn default_jwks_equals_the_recorded_reference_jwks() {
    assert_eq!(
        jwks_document(
            &fixture_keys()
                .validation_keys()
                .cloned()
                .map(std::sync::Arc::new)
                .collect::<Vec<_>>()
        ),
        recorded("discovery-jwks.json")
    );
}

#[test]
fn entries_follow_the_fixed_order() {
    let options = ProtocolOptions::default();
    let d = doc(&options, &fixture_keys(), &reference_features());
    let keys: Vec<&String> = d.as_object().unwrap().keys().collect();
    assert_eq!(
        &keys[..4],
        [
            "issuer",
            "jwks_uri",
            "authorization_endpoint",
            "token_endpoint"
        ]
    );
    assert_eq!(
        keys.last().unwrap().as_str(),
        "dpop_signing_alg_values_supported"
    );
}

#[test]
fn disabled_endpoints_drop_their_urls_and_signing_algorithms() {
    let mut options = ProtocolOptions::default();
    options.endpoints.enable_user_info_endpoint = false;
    options.endpoints.enable_introspection_endpoint = false;
    let d = doc(&options, &fixture_keys(), &reference_features());
    for key in [
        "userinfo_endpoint",
        "introspection_endpoint",
        "userinfo_signing_alg_values_supported",
        "introspection_signing_alg_values_supported",
    ] {
        assert!(d.get(key).is_none(), "{key} should be absent");
    }
    assert_eq!(d["id_token_signing_alg_values_supported"], json!(["RS256"]));
}

#[test]
fn authorize_disabled_drops_request_and_prompt_entries() {
    let mut options = ProtocolOptions::default();
    options.endpoints.enable_authorize_endpoint = false;
    let d = doc(&options, &fixture_keys(), &reference_features());
    for key in [
        "authorization_endpoint",
        "request_parameter_supported",
        "request_object_signing_alg_values_supported",
        "prompt_values_supported",
    ] {
        assert!(d.get(key).is_none(), "{key} should be absent");
    }
}

#[test]
fn private_key_jwt_adds_method_and_signing_algorithms_unless_empty() {
    let features = DiscoveryFeatures {
        private_key_jwt: true,
        ..reference_features()
    };
    let mut options = ProtocolOptions {
        supported_client_assertion_signing_algorithms: vec!["RS256".into(), "ES256".into()],
        ..Default::default()
    };
    let d = doc(&options, &fixture_keys(), &features);
    assert_eq!(
        d["token_endpoint_auth_methods_supported"],
        json!([
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt"
        ])
    );
    assert_eq!(
        d["revocation_endpoint_auth_signing_alg_values_supported"],
        json!(["RS256", "ES256"])
    );

    options
        .supported_client_assertion_signing_algorithms
        .clear();
    let d = doc(&options, &fixture_keys(), &features);
    assert!(
        d.get("token_endpoint_auth_signing_alg_values_supported")
            .is_none()
    );
}

#[test]
fn empty_algorithm_lists_are_omitted() {
    let mut options = ProtocolOptions::default();
    options.supported_request_object_signing_algorithms.clear();
    options.dpop.supported_dpop_signing_algorithms.clear();
    let d = doc(&options, &fixture_keys(), &reference_features());
    for key in [
        "request_object_signing_alg_values_supported",
        "backchannel_authentication_request_signing_alg_values_supported",
        "dpop_signing_alg_values_supported",
    ] {
        assert!(d.get(key).is_none(), "{key} should be absent");
    }
}

#[test]
fn no_keys_or_hidden_key_set_omits_jwks_uri_and_signing_algorithms() {
    let options = ProtocolOptions::default();
    let d = doc(&options, &KeyMaterial::default(), &reference_features());
    assert!(d.get("jwks_uri").is_none());
    assert!(d.get("id_token_signing_alg_values_supported").is_none());

    let mut hidden = ProtocolOptions::default();
    hidden.discovery.show_key_set = false;
    assert!(
        doc(&hidden, &fixture_keys(), &reference_features())
            .get("jwks_uri")
            .is_none()
    );
}

#[test]
fn custom_entries_expand_relative_paths_and_never_override_standard_entries() {
    let options: ProtocolOptions = serde_json::from_value(json!({
        "discovery": { "custom_entries": { "issuer": "ignored", "foo": "bar", "relative": "~/custom/path", "nested": { "a": 1 } } }
    }))
    .unwrap();
    let d = doc(&options, &fixture_keys(), &reference_features());
    assert_eq!(d["issuer"], "https://idsrv.test");
    assert_eq!(d["foo"], "bar");
    assert_eq!(d["relative"], "{base}/custom/path");
    assert_eq!(d["nested"], json!({ "a": 1 }));
}

#[test]
fn hidden_claims_and_scopes_are_omitted() {
    let mut options = ProtocolOptions::default();
    options.discovery.show_claims = false;
    options.discovery.show_api_scopes = false;
    let d = doc(&options, &fixture_keys(), &reference_features());
    assert!(d.get("claims_supported").is_none());
    assert_eq!(d["scopes_supported"], json!(["openid", "profile"]));
}

#[test]
fn grant_types_follow_features_and_enabled_endpoints() {
    let mut options = ProtocolOptions::default();
    options.endpoints.enable_device_authorization_endpoint = false;
    let features = DiscoveryFeatures {
        password_grant: false,
        extension_grants: vec!["custom".into()],
        private_key_jwt: false,
    };
    let d = doc(&options, &fixture_keys(), &features);
    assert_eq!(
        d["grant_types_supported"],
        json!([
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "implicit",
            "urn:openid:params:grant-type:ciba",
            "custom"
        ])
    );
}

#[test]
fn mtls_adds_aliases_auth_methods_and_bound_tokens() {
    let keys = fixture_keys();
    let mut options = ProtocolOptions::default();
    options.mutual_tls.enabled = true;
    let d = doc(&options, &keys, &reference_features());
    assert_eq!(
        d["mtls_endpoint_aliases"],
        json!({
            "token_endpoint": "{base}/connect/mtls/token",
            "revocation_endpoint": "{base}/connect/mtls/revocation",
            "introspection_endpoint": "{base}/connect/mtls/introspect",
            "device_authorization_endpoint": "{base}/connect/mtls/deviceauthorization",
            "pushed_authorization_request_endpoint": "{base}/connect/mtls/par",
        })
    );
    assert_eq!(d["tls_client_certificate_bound_access_tokens"], true);
    let methods = json!([
        "client_secret_basic",
        "client_secret_post",
        "tls_client_auth",
        "self_signed_tls_client_auth"
    ]);
    assert_eq!(d["token_endpoint_auth_methods_supported"], methods);
    assert_eq!(d["revocation_endpoint_auth_methods_supported"], methods);
    assert_eq!(d["introspection_endpoint_auth_methods_supported"], methods);

    options.mutual_tls.domain_name = Some("mtls.idsrv.test".into());
    let d = doc(&options, &keys, &reference_features());
    assert_eq!(
        d["mtls_endpoint_aliases"]["token_endpoint"],
        "https://mtls.idsrv.test/connect/token"
    );
    options.mutual_tls.domain_name = Some("mtls".into());
    let mut ctx_doc = {
        let resources = fixture_resources();
        let algorithms = keys.signing_algorithms();
        let features = reference_features();
        let ctx = DiscoveryContext {
            options: &options,
            resources: &resources,
            has_validation_keys: true,
            signing_algorithms: &algorithms,
            features: &features,
            base_url: "https://idsrv.test:8443/base",
            issuer: "https://idsrv.test",
        };
        Value::Object(discovery_document(&ctx))
    };
    assert_eq!(
        ctx_doc["mtls_endpoint_aliases"]["token_endpoint"].take(),
        "https://mtls.idsrv.test:8443/base/connect/token"
    );

    let d = doc(&ProtocolOptions::default(), &keys, &reference_features());
    assert!(d.get("mtls_endpoint_aliases").is_none());
    assert!(
        d.get("tls_client_certificate_bound_access_tokens")
            .is_none()
    );
}

#[test]
fn discovery_with_jarm() {
    let mut options = ProtocolOptions {
        issuer_uri: Some("https://idsrv.test".into()),
        ..Default::default()
    };
    options.jarm.enabled = true;
    let keys = fixture_keys();
    let doc = doc(&options, &keys, &reference_features());
    assert_eq!(
        doc["response_modes_supported"],
        json!([
            "form_post",
            "query",
            "fragment",
            "query.jwt",
            "fragment.jwt",
            "form_post.jwt",
            "jwt"
        ])
    );
    assert_eq!(
        doc["authorization_signing_alg_values_supported"],
        json!(keys.signing_algorithms())
    );
}

#[test]
fn discovery_without_jarm_is_unchanged() {
    let options = ProtocolOptions {
        issuer_uri: Some("https://idsrv.test".into()),
        ..Default::default()
    };
    let doc = doc(&options, &fixture_keys(), &reference_features());
    assert!(
        doc.get("authorization_signing_alg_values_supported")
            .is_none()
    );
    assert_eq!(
        doc["response_modes_supported"],
        json!(["form_post", "query", "fragment"])
    );
    assert_eq!(doc, recorded("discovery-document.json"));
}

fn with_registration(
    mode: rustid_core::options::RegistrationEndpointMode,
    url: Option<&str>,
) -> Value {
    let mut options = ProtocolOptions {
        issuer_uri: Some("https://idsrv.test".into()),
        ..Default::default()
    };
    options.discovery.dynamic_client_registration =
        rustid_core::options::DynamicClientRegistrationDiscoveryOptions {
            registration_endpoint_mode: mode,
            static_registration_endpoint: url.map(str::to_owned),
        };
    doc(&options, &fixture_keys(), &reference_features())
}

#[test]
fn registration_endpoint_is_the_static_one() {
    let doc = with_registration(
        rustid_core::options::RegistrationEndpointMode::Static,
        Some("https://custom.example.com/register"),
    );
    assert_eq!(
        doc["registration_endpoint"],
        "https://custom.example.com/register"
    );
}

#[test]
fn registration_endpoint_is_inferred() {
    let doc = with_registration(
        rustid_core::options::RegistrationEndpointMode::Inferred,
        None,
    );
    assert_eq!(doc["registration_endpoint"], "{base}/connect/dcr");
    // After dpop_signing_alg_values_supported.
    let keys: Vec<&String> = doc.as_object().unwrap().keys().collect();
    let dpop = keys
        .iter()
        .position(|k| *k == "dpop_signing_alg_values_supported")
        .unwrap();
    assert_eq!(keys[dpop + 1], "registration_endpoint");
}

#[test]
fn registration_endpoint_is_absent_by_default_and_static_without_url() {
    use rustid_core::options::RegistrationEndpointMode::{None as Off, Static};
    assert!(
        with_registration(Off, None)
            .get("registration_endpoint")
            .is_none()
    );
    assert!(
        with_registration(Static, None)
            .get("registration_endpoint")
            .is_none()
    );
}

#[test]
fn pairwise_is_listed_only_with_a_salt() {
    let keys = fixture_keys();
    let features = reference_features();
    let mut options = ProtocolOptions::default();
    assert_eq!(
        doc(&options, &keys, &features)["subject_types_supported"],
        json!(["public"])
    );
    options.pairwise.salt = Some("server-salt-0123456789".into());
    assert_eq!(
        doc(&options, &keys, &features)["subject_types_supported"],
        json!(["public", "pairwise"])
    );
}
