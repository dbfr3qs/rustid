mod support;

use rustid_core::authorize::implicit::{browser_response_parameters, browser_tokens};
use rustid_core::authorize::validate;
use rustid_core::issuance::Issuer;
use rustid_core::params::Params;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::tokens::{Claim, hash_claim_value};
use support::{Fixture, ISSUER};

fn session() -> UserSession {
    UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            claims: vec![
                Claim::string("name", "Alice"),
                Claim::string("role", "admin"),
            ],
            ..Default::default()
        },
        None,
        chrono::Utc::now(),
        3600,
    )
}

async fn issue(
    f: &Fixture,
    client: &str,
    response_type: &str,
    scope: &str,
    code: Option<&str>,
) -> (rustid_core::authorize::implicit::BrowserTokens, Params) {
    let redirect = if client == "spa" {
        "https://spa.test/cb"
    } else {
        "https://client.test/callback"
    };
    let params = Params::from_pairs([
        ("client_id", client),
        ("redirect_uri", redirect),
        ("response_type", response_type),
        ("scope", scope),
        ("state", "s1"),
        ("nonce", "n1"),
    ]);
    let s = session();
    let request = validate(&f.authorize_ctx(chrono::Utc::now()), params, Some(&s))
        .await
        .unwrap();
    let issuer = Issuer {
        options: &f.options,
        stores: &f.stores,
        keys: &f.keys,
        issuer: ISSUER,
        now: chrono::Utc::now(),
    };
    let tokens = browser_tokens(&issuer, &request, code).await.unwrap();
    let response = browser_response_parameters(&request, &tokens);
    (tokens, response)
}

fn claims(jwt: &str) -> serde_json::Map<String, serde_json::Value> {
    rustid_core::jwt::Jws::decode(jwt).unwrap().payload
}

#[tokio::test]
async fn an_id_token_alone_carries_the_identity_claims() {
    let f = Fixture::new();
    let (tokens, params) = issue(&f, "spa", "id_token", "openid profile", None).await;
    let id = claims(tokens.id_token.as_deref().unwrap());
    assert_eq!(id["name"], "Alice");
    assert_eq!(id["nonce"], "n1");
    assert!(tokens.access_token.is_none());
    let keys: Vec<&str> = params.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["id_token", "state", "session_state"]);
}

#[tokio::test]
async fn with_an_access_token_or_code_requested_identity_claims_stay_out() {
    let f = Fixture::new();
    let (tokens, params) = issue(&f, "spa", "id_token token", "openid profile api1", None).await;
    let id = claims(tokens.id_token.as_deref().unwrap());
    assert!(id.get("name").is_none());
    assert_eq!(
        id["at_hash"],
        hash_claim_value(tokens.access_token.as_deref().unwrap(), "RS256").as_str()
    );
    let access = claims(tokens.access_token.as_deref().unwrap());
    assert_eq!(access["role"], "admin");
    let keys: Vec<&str> = params.iter().map(|(k, _)| k).collect();
    assert_eq!(
        keys,
        [
            "id_token",
            "access_token",
            "token_type",
            "expires_in",
            "scope",
            "state",
            "session_state"
        ]
    );

    let (tokens, params) = issue(
        &f,
        "hybrid",
        "code id_token",
        "openid profile",
        Some("CODE"),
    )
    .await;
    let id = claims(tokens.id_token.as_deref().unwrap());
    assert!(
        id.get("name").is_none(),
        "the client can still redeem the code for an access token"
    );
    assert_eq!(id["c_hash"], hash_claim_value("CODE", "RS256").as_str());
    let keys: Vec<&str> = params.iter().map(|(k, _)| k).collect();
    assert_eq!(keys, ["code", "id_token", "state", "session_state"]);
}
