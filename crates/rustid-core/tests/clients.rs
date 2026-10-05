use std::path::Path;

use chrono::{TimeZone, Utc};
use rustid_core::clients::{AccessTokenType, Client, Clients, Secret, validate_client};

fn fixture_clients() -> Clients {
    Clients::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/clients.json"))
        .unwrap()
}

fn client(json: &str) -> Client {
    serde_json::from_str(json).unwrap()
}

#[test]
fn defaults_hold() {
    let c = client(r#"{ "clientId": "c" }"#);
    assert!(c.enabled && c.require_client_secret && c.include_jwt_id);
    assert_eq!(c.protocol_type, "oidc");
    assert_eq!(c.access_token_lifetime, 3600);
    assert_eq!(c.identity_token_lifetime, 300);
    assert_eq!(c.access_token_type, AccessTokenType::Jwt);
    assert_eq!(c.client_claims_prefix.as_deref(), Some("client_"));
}

#[test]
fn unknown_fixture_properties_are_ignored() {
    let c = client(r#"{ "clientId": "c", "requirePkce": true, "somethingNew": [1, 2] }"#);
    assert_eq!(c.client_id, "c");
}

#[test]
fn access_token_type_accepts_names_in_any_case_and_numbers() {
    for (json, expected) in [
        (r#""Reference""#, AccessTokenType::Reference),
        (r#""jwt""#, AccessTokenType::Jwt),
        ("1", AccessTokenType::Reference),
    ] {
        let c = client(&format!(
            r#"{{ "clientId": "c", "accessTokenType": {json} }}"#
        ));
        assert_eq!(c.access_token_type, expected, "{json}");
    }
    assert!(serde_json::from_str::<Client>(r#"{ "accessTokenType": "Opaque" }"#).is_err());
}

#[test]
fn secret_expiration_with_or_without_offset_is_utc() {
    let with: Secret =
        serde_json::from_str(r#"{ "value": "x", "expiration": "2001-01-01T00:00:00Z" }"#).unwrap();
    let without: Secret =
        serde_json::from_str(r#"{ "value": "x", "expiration": "2001-01-01T00:00:00" }"#).unwrap();
    let expected = Utc.with_ymd_and_hms(2001, 1, 1, 0, 0, 0).unwrap();
    assert_eq!(with.expiration, Some(expected));
    assert_eq!(without.expiration, Some(expected));
    assert!(with.has_expired(Utc::now()));
    assert!(!with.has_expired(expected), "expiry is strictly before now");
    assert_eq!(with.secret_type, "SharedSecret");
}

#[test]
fn cors_origins_match_case_insensitively_on_the_configured_url_origin() {
    let clients = Clients {
        clients: vec![client(
            r#"{ "clientId": "c", "allowedCorsOrigins": ["https://App.Test:8443"] }"#,
        )],
    };
    assert!(clients.is_cors_origin_allowed("https://app.test:8443"));
    assert!(clients.is_cors_origin_allowed("HTTPS://APP.TEST:8443"));
    assert!(!clients.is_cors_origin_allowed("https://app.test"));
    assert!(!clients.is_cors_origin_allowed("https://app.test:8443/"));
}

#[test]
fn every_fixture_client_except_the_deliberately_invalid_ones_validates() {
    let invalid: Vec<String> = fixture_clients()
        .clients
        .iter()
        .filter(|c| validate_client(c, false).is_err())
        .map(|c| c.client_id.clone())
        .collect();
    assert_eq!(invalid, ["client.no_secret", "implicit_and_client_creds"]);
}

#[test]
fn configuration_validation_rules() {
    let err = |json: &str| validate_client(&client(json), false).unwrap_err();
    assert!(err(r#"{ "clientId": "c" }"#).contains("no allowed grant type"));
    assert!(err(r#"{ "clientId": "c", "allowedGrantTypes": ["client_credentials"], "clientSecrets": [{"value": "x"}], "accessTokenLifetime": 0 }"#).contains("access token lifetime"));
    assert!(err(r#"{ "clientId": "c", "allowedGrantTypes": ["authorization_code"], "requireClientSecret": false }"#).contains("No redirect URI"));
    assert!(err(r#"{ "clientId": "c", "allowedGrantTypes": ["implicit"], "redirectUris": ["javascript:alert(1)"] }"#).contains("invalid scheme"));
    assert!(err(r#"{ "clientId": "c", "allowedGrantTypes": ["implicit"], "redirectUris": ["https://x"], "allowedCorsOrigins": ["https://x/"] }"#).contains("invalid origin"));
    assert!(
        err(r#"{ "clientId": "c", "allowedGrantTypes": ["client_credentials"] }"#)
            .contains("no client secret is configured")
    );
    assert!(err(r#"{ "clientId": "c", "allowedGrantTypes": ["client_credentials"], "requireClientSecret": false }"#).contains("RequireClientSecret is false"));
    // Non-OIDC clients are not validated here.
    assert!(
        validate_client(
            &client(r#"{ "clientId": "c", "protocolType": "saml2p" }"#),
            false
        )
        .is_ok()
    );
    // PAR may allow a confidential client without registered redirect URIs.
    let par = client(
        r#"{ "clientId": "c", "allowedGrantTypes": ["authorization_code"], "clientSecrets": [{"value": "x"}] }"#,
    );
    assert!(validate_client(&par, false).is_err());
    assert!(validate_client(&par, true).is_ok());
}

#[test]
fn lifetimes_outside_the_int_range_do_not_load() {
    // Client lifetimes are 32-bit, so such a configuration can't load.
    for field in [
        "accessTokenLifetime",
        "identityTokenLifetime",
        "absoluteRefreshTokenLifetime",
        "slidingRefreshTokenLifetime",
        "deviceCodeLifetime",
    ] {
        let json = format!(r#"{{"clientId": "c", "{field}": 9000000000000000}}"#);
        assert!(serde_json::from_str::<Client>(&json).is_err(), "{field}");
    }
    let json = r#"{"clientId": "c", "accessTokenLifetime": 2147483647}"#;
    assert_eq!(client(json).access_token_lifetime, 2147483647);
}

#[test]
fn duplicate_client_ids_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("clients.json");
    std::fs::write(
        &path,
        r#"[{"clientId": "m2m"}, {"clientId": "other"}, {"clientId": "m2m"}]"#,
    )
    .unwrap();
    let err = Clients::load(&path).unwrap_err();
    assert!(
        matches!(&err, rustid_core::clients::ClientsError::Duplicate { client_id, .. } if client_id == "m2m"),
        "{err}"
    );
    std::fs::write(&path, r#"[{"clientId": "a"}, {"clientId": "A"}]"#).unwrap();
    assert!(Clients::load(&path).is_ok(), "ids compare case-sensitively");
}

#[test]
fn authorize_settings_default_and_load_from_fixtures() {
    let c = client(r#"{ "clientId": "c" }"#);
    assert!(c.require_pkce && c.enable_local_login);
    assert!(!c.allow_plain_text_pkce && !c.allow_access_tokens_via_browser);
    assert!(!c.require_request_object && !c.require_pushed_authorization && !c.require_consent);
    assert!(c.identity_provider_restrictions.is_empty());
    assert_eq!(c.user_sso_lifetime, None);

    let c = client(
        r#"{ "clientId": "c", "requirePkce": false, "allowPlainTextPkce": true,
             "allowAccessTokensViaBrowser": true, "requireRequestObject": true,
             "requirePushedAuthorization": true, "requireConsent": true,
             "enableLocalLogin": false, "identityProviderRestrictions": ["google"],
             "userSsoLifetime": 600 }"#,
    );
    assert!(!c.require_pkce && c.allow_plain_text_pkce && c.allow_access_tokens_via_browser);
    assert!(c.require_request_object && c.require_pushed_authorization && c.require_consent);
    assert!(!c.enable_local_login);
    assert_eq!(c.identity_provider_restrictions, ["google"]);
    assert_eq!(c.user_sso_lifetime, Some(600));

    let fixtures = fixture_clients();
    let web_idp = fixtures
        .clients
        .iter()
        .find(|c| c.client_id == "web.idp")
        .unwrap();
    assert_eq!(web_idp.identity_provider_restrictions, ["google"]);
}

#[test]
fn code_settings_default() {
    let c = client(r#"{ "clientId": "c" }"#);
    assert_eq!(c.authorization_code_lifetime, 300);
    assert!(c.allow_remember_consent);
    let c = client(
        r#"{ "clientId": "c", "authorizationCodeLifetime": 60, "allowRememberConsent": false }"#,
    );
    assert_eq!(c.authorization_code_lifetime, 60);
    assert!(!c.allow_remember_consent);
}

#[test]
fn identity_token_settings_default() {
    let c = client(r#"{ "clientId": "c" }"#);
    assert!(c.allowed_identity_token_signing_algorithms.is_empty());
    assert!(!c.always_include_user_claims_in_id_token);
    let c = client(
        r#"{ "clientId": "c", "allowedIdentityTokenSigningAlgorithms": ["ES256"], "alwaysIncludeUserClaimsInIdToken": true }"#,
    );
    assert_eq!(c.allowed_identity_token_signing_algorithms, ["ES256"]);
    assert!(c.always_include_user_claims_in_id_token);
}

/// The pairwise subject salt round-trips; nothing derives
/// pairwise subjects from it.
#[test]
fn the_pairwise_subject_salt_is_kept() {
    let client: rustid_core::clients::Client =
        serde_json::from_str(r#"{"clientId":"c","pairWiseSubjectSalt":"pepper"}"#).unwrap();
    assert_eq!(client.pair_wise_subject_salt.as_deref(), Some("pepper"));
}

#[test]
fn every_fixture_client_round_trips_through_json() {
    for c in fixture_clients().clients {
        let json = serde_json::to_value(&c).unwrap();
        let back: Client = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back, c, "{} via {json}", c.client_id);
    }
}

#[test]
fn non_default_client_settings_round_trip() {
    let c = client(
        r#"{ "clientId": "c", "accessTokenType": "Reference", "refreshTokenUsage": "OneTimeOnly",
             "refreshTokenExpiration": "Sliding", "dPoPValidationMode": "Iat, Nonce",
             "dPoPClockSkew": "1.01:01:01", "claims": [{ "type": "t", "value": "v" }],
             "clientSecrets": [{ "value": "h", "expiration": "2030-01-01T00:00:00Z" }] }"#,
    );
    let json = serde_json::to_value(&c).unwrap();
    assert_eq!(json["accessTokenType"], "Reference");
    assert_eq!(json["refreshTokenUsage"], "OneTimeOnly");
    assert_eq!(json["refreshTokenExpiration"], "Sliding");
    assert_eq!(json["dPoPValidationMode"], "IatAndNonce");
    assert_eq!(json["dPoPClockSkew"], "1.01:01:01");
    assert_eq!(json["requireDPoP"], false);
    assert_eq!(serde_json::from_value::<Client>(json).unwrap(), c);
}

#[test]
fn timespans_serialize_as_text() {
    use rustid_core::options::TimeSpan;
    assert_eq!(serde_json::to_value(TimeSpan(300)).unwrap(), "00:05:00");
    assert_eq!(serde_json::to_value(TimeSpan(90061)).unwrap(), "1.01:01:01");
    assert_eq!(serde_json::to_value(TimeSpan(-30)).unwrap(), "-00:00:30");
}
