//! A bundle's grant models become rustid's records.

use rustid_server::import::{
    GrantRow, translate_consent, translate_reference_token, translate_refresh_token,
};

fn rows() -> Vec<GrantRow> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/migration/bundle-grants.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn row(grant_type: &str) -> GrantRow {
    rows()
        .into_iter()
        .find(|r| r.grant_type == grant_type)
        .unwrap()
}

#[test]
fn refresh_token_claims_survive_translation() {
    let row = row("refresh_token");
    let grant = translate_refresh_token(&row).unwrap();
    assert_eq!(grant.key, row.key);
    assert_eq!(grant.grant_type, "refresh_token");
    assert_eq!(grant.subject_id.as_deref(), Some("alice"));
    assert_eq!(grant.expiration, row.expiration);
    let token: rustid_core::refresh_tokens::RefreshToken =
        serde_json::from_str(&grant.data).unwrap();
    assert_eq!(token.client_id, "web");
    assert_eq!(token.subject.subject_id, "alice");
    assert_eq!(token.subject.session_id, "9A4F2E1B8C7D6E5F4A3B2C1D0E9F8A7B");
    assert_eq!(token.subject.auth_time, 1790928000);
    assert_eq!(token.subject.idp, "local");
    assert_eq!(token.subject.amr, vec!["pwd", "mfa"]);
    let claim = |t: &str| token.subject.claims.iter().find(|c| c.claim_type == t);
    assert_eq!(claim("tenant").unwrap().value, "t1");
    assert_eq!(claim("name").unwrap().value, "Alice Smith");
    assert!(claim("sub").is_none() && claim("amr").is_none());
    assert_eq!(
        token.authorized_scopes,
        vec!["openid", "api1", "offline_access"]
    );
    assert_eq!(token.lifetime, 2592000);
    assert_eq!(token.consumed_time, None);
    let access = token.access_token.unwrap();
    assert_eq!(access.token.client_id, "web");
    assert_eq!(access.token.audiences, vec!["api1-resource"]);
    assert_eq!(access.token.lifetime, 3600);
    assert_eq!(
        access.jti.as_deref(),
        Some("6C2D9F0E1A2B3C4D5E6F7A8B9C0D1E2F")
    );
    assert_eq!(
        access
            .token
            .claims
            .iter()
            .filter(|c| c.claim_type == "amr")
            .count(),
        2
    );
}

#[test]
fn reference_tokens_translate() {
    let row = row("reference_token");
    let grant = translate_reference_token(&row).unwrap();
    assert_eq!(grant.key, row.key);
    let token: rustid_core::reference_tokens::ReferenceToken =
        serde_json::from_str(&grant.data).unwrap();
    assert_eq!(token.client_id, "web");
    assert_eq!(token.subject_id.as_deref(), Some("alice"));
    assert_eq!(token.description.as_deref(), Some("laptop"));
    assert_eq!(token.lifetime, 3600);
    assert!(
        token
            .claims
            .iter()
            .any(|c| c.claim_type == "scope" && c.value == "api1")
    );
}

#[test]
fn consents_translate() {
    let row = row("user_consent");
    let grant = translate_consent(&row).unwrap();
    assert_eq!(grant.key, row.key);
    let consent: rustid_core::consent::UserConsent = serde_json::from_str(&grant.data).unwrap();
    assert_eq!(consent.subject_id, "alice");
    assert_eq!(consent.scopes, vec!["openid", "api1"]);
    assert_eq!(consent.expiration, None);
}

#[test]
fn a_malformed_grant_names_its_key() {
    let mut row = row("refresh_token");
    row.data = serde_json::json!({ "Lifetime": "soon" });
    let error = translate_refresh_token(&row).unwrap_err();
    assert!(error.to_string().contains(&row.key), "{error}");
}
