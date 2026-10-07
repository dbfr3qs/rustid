use std::sync::Arc;

use rustid_core::clients::{Client, ClientClaim};
use rustid_core::options::ProtocolOptions;
use rustid_core::profile::requested_claims;
use rustid_core::resources::{ApiResource, ApiScope, IdentityResource};
use rustid_core::scopes::ValidatedResources;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::tokens::{
    Claim, IdentityTokenRequest, access_token_claim_types, hash_claim_value, identity_token,
    identity_token_claim_types, includes_identity_claims, jwt_payload, user_access_token,
};

fn session() -> UserSession {
    UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            auth_time: Some(1_800_000_000),
            claims: vec![
                Claim::string("name", "Alice"),
                Claim::string("role", "admin"),
                Claim::string("role", "user"),
                Claim::string("sub", "forged"),
                Claim::string("email", "a@x.test"),
            ],
            ..Default::default()
        },
        None,
        chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        3600,
    )
}

fn resources() -> ValidatedResources {
    ValidatedResources {
        identity_resources: vec![IdentityResource {
            name: "profile".into(),
            user_claims: vec!["name".into(), "sub".into()],
            ..Default::default()
        }],
        api_scopes: vec![ApiScope {
            name: "api1".into(),
            user_claims: vec!["email".into()],
            ..Default::default()
        }],
        api_resources: vec![ApiResource {
            name: "api".into(),
            scopes: vec!["api1".into()],
            user_claims: vec!["role".into()],
            ..Default::default()
        }],
        offline_access: true,
        scopes: vec![
            "openid".into(),
            "profile".into(),
            "offline_access".into(),
            "api1".into(),
        ],
    }
}

fn types(claims: &[Claim]) -> Vec<String> {
    claims
        .iter()
        .map(|c| format!("{}={}", c.claim_type, c.value))
        .collect()
}

#[test]
fn hash_claims_take_the_left_half_of_the_algorithms_hash() {
    assert_eq!(hash_claim_value("state", "RS256"), "S6aXNcpTdl7WpwnttWxuog");
    assert_eq!(
        hash_claim_value("state", "ES384"),
        "2-SHqHlgTYFXyolylsqnIU83EkNod_cC"
    );
    assert_eq!(
        hash_claim_value("state", "PS512"),
        "wxdMg1Rrq6ZiuGEtYXXuetfiP7T8Jc7PybEN4OjAqAc"
    );
    assert_eq!(
        hash_claim_value("stäte", "RS256"),
        "sb_0BYeJvGZTk64HMrdK4w",
        "non-ASCII hashes as '?'"
    );
}

/// What the default profile service answers for an access token.
fn access_profile(session: &UserSession) -> Vec<Claim> {
    requested_claims(&session.claims, &access_token_claim_types(&resources()))
}

#[test]
fn user_access_tokens_carry_scopes_subject_profile_claims_and_sid() {
    let client = Client {
        client_id: "web".into(),
        claims: vec![ClientClaim {
            claim_type: "tier".into(),
            value: "gold".into(),
            value_type: rustid_core::clients::CLAIM_VALUE_TYPE_STRING.into(),
        }],
        ..Default::default()
    };
    let token = user_access_token(
        &ProtocolOptions::default(),
        "https://i",
        &client,
        &resources(),
        &session(),
        Some("SID"),
        access_profile(&session()),
    );
    assert_eq!(
        types(&token.claims),
        [
            "client_id=web",
            "scope=openid",
            "scope=profile",
            "scope=api1",
            "scope=offline_access",
            "sub=1",
            "auth_time=1800000000",
            "idp=local",
            "amr=pwd",
            "role=admin",
            "role=user",
            "email=a@x.test",
            "sid=SID",
        ],
        "client claims only with always_send_client_claims; protocol claims never from the profile"
    );
    assert_eq!(token.audiences, ["api"]);
    let with_client_claims = Client {
        always_send_client_claims: true,
        ..client
    };
    let token = user_access_token(
        &ProtocolOptions::default(),
        "https://i",
        &with_client_claims,
        &resources(),
        &session(),
        None,
        access_profile(&session()),
    );
    assert!(types(&token.claims).contains(&"client_tier=gold".to_owned()));
    assert!(!types(&token.claims).iter().any(|c| c.starts_with("sid=")));
}

#[test]
fn identity_tokens_hash_the_access_token_and_add_identity_claims_on_request() {
    let client = Arc::new(Client {
        client_id: "web".into(),
        identity_token_lifetime: 120,
        ..Default::default()
    });
    let request = IdentityTokenRequest {
        subject: None,
        nonce: Some("n"),
        access_token: Some("token"),
        authorization_code: Some("code"),
        state_hash: Some("sh"),
        session_id: Some("SID"),
        include_all_identity_claims: false,
    };
    let token = identity_token(
        "https://i",
        &client,
        &session(),
        &request,
        "RS256",
        Vec::new(),
    );
    assert_eq!(
        types(&token.claims),
        [
            "nonce=n",
            &format!("at_hash={}", hash_claim_value("token", "RS256")),
            &format!("c_hash={}", hash_claim_value("code", "RS256")),
            "s_hash=sh",
            "sid=SID",
            "sub=1",
            "auth_time=1800000000",
            "idp=local",
            "amr=pwd",
        ]
    );
    assert_eq!(
        (token.audiences.as_slice(), token.lifetime),
        (&["web".to_owned()][..], 120)
    );
    let all = IdentityTokenRequest {
        subject: None,
        include_all_identity_claims: true,
        ..request
    };
    assert!(includes_identity_claims(&client, &all));
    let profile = requested_claims(&session().claims, &identity_token_claim_types(&resources()));
    let token = identity_token("https://i", &client, &session(), &all, "RS256", profile);
    assert_eq!(
        types(&token.claims).last().map(String::as_str),
        Some("name=Alice")
    );
}

#[test]
fn payloads_write_amr_as_an_array_of_distinct_values() {
    let client = Client {
        client_id: "web".into(),
        ..Default::default()
    };
    let mut s = session();
    s.amr = vec!["pwd".into(), "mfa".into(), "pwd".into()];
    let token = user_access_token(
        &ProtocolOptions::default(),
        "https://i",
        &client,
        &resources(),
        &s,
        None,
        access_profile(&s),
    );
    let payload = jwt_payload(&ProtocolOptions::default(), &token, 100, None).unwrap();
    assert_eq!(payload["amr"], serde_json::json!(["pwd", "mfa"]));
    assert_eq!(payload["auth_time"], serde_json::json!(1_800_000_000));
    assert_eq!(payload["role"], serde_json::json!(["admin", "user"]));
    let keys: Vec<&str> = payload.keys().map(String::as_str).collect();
    assert_eq!(
        &keys[..7],
        ["iss", "nbf", "iat", "exp", "aud", "scope", "amr"]
    );
}
