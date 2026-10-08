mod support;

use rustid_core::access_tokens::ValidationContext;
use rustid_core::issuance::Issuer;
use rustid_core::scopes::validate_requested_resources;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::tokens::Claim;
use rustid_core::userinfo::userinfo;
use support::{Fixture, ISSUER};

fn session() -> UserSession {
    UserSession::sign_in(
        SignIn {
            subject_id: "1".into(),
            claims: vec![
                Claim::string("name", "Alice"),
                Claim::string("role", "admin"),
                // `profile` asks for it, but `api1` doesn't put it in
                // access tokens, so userinfo never sees it.
                Claim::string("given_name", "Alice"),
            ],
            ..Default::default()
        },
        None,
        chrono::Utc::now(),
        3600,
    )
}

async fn token(f: &Fixture, scopes: &[&str], issued: chrono::DateTime<chrono::Utc>) -> String {
    let client = f
        .clients
        .clients
        .iter()
        .find(|c| c.client_id == "web")
        .unwrap()
        .clone();
    let requested: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    let resources =
        validate_requested_resources(&client, &f.resources.enabled(), &requested, &[]).unwrap();
    let issuer = Issuer {
        options: &f.options,
        stores: &f.stores,
        keys: &f.keys,
        issuer: ISSUER,
        now: issued,
    };
    issuer
        .user_access_token(&client, &resources, &session(), Some("SID"), None)
        .await
        .unwrap()
}

fn ctx(f: &Fixture) -> ValidationContext<'_> {
    ValidationContext {
        options: &f.options,
        stores: &f.stores,
        keys: &f.keys,
        issuer: ISSUER,
        now: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn userinfo_returns_the_identity_claims_the_token_carries() {
    let f = Fixture::new();
    let t = token(&f, &["openid", "profile", "api1"], chrono::Utc::now()).await;
    let claims = userinfo(&ctx(&f), &t).await.unwrap().unwrap();
    assert_eq!(
        serde_json::Value::Object(claims),
        serde_json::json!({ "name": "Alice", "sub": "1" }),
        "role is in the token but no identity scope asks for it; given_name is in the session but not the token"
    );
    let t = token(&f, &["openid", "api1"], chrono::Utc::now()).await;
    let claims = userinfo(&ctx(&f), &t).await.unwrap().unwrap();
    assert_eq!(
        serde_json::Value::Object(claims),
        serde_json::json!({ "sub": "1" })
    );
}

#[tokio::test]
async fn userinfo_needs_a_valid_token_with_the_openid_scope() {
    let f = Fixture::new();
    let t = token(&f, &["api1"], chrono::Utc::now()).await;
    assert_eq!(
        userinfo(&ctx(&f), &t).await.unwrap(),
        Err("insufficient_scope")
    );
    assert_eq!(
        userinfo(&ctx(&f), "nope").await.unwrap(),
        Err("invalid_token")
    );
    let old = token(
        &f,
        &["openid", "api1"],
        chrono::Utc::now() - chrono::Duration::hours(3),
    )
    .await;
    assert_eq!(
        userinfo(&ctx(&f), &old).await.unwrap(),
        Err("expired_token")
    );
}

/// A pairwise client on a server whose salt has gone (one instance deployed
/// without it): its subjects can't be made, and nothing falls back to the
/// user's own.
#[tokio::test]
async fn a_pairwise_client_without_a_salt_fails_closed() {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        for c in clients.iter_mut().filter(|c| c.client_id == "web") {
            c.subject_type = rustid_core::clients::SubjectType::Pairwise;
        }
    });
    // An access token issued while there was no salt either; the id token
    // and userinfo answer are refused.
    let t = token(&f, &["openid", "api1"], chrono::Utc::now()).await;
    assert!(
        userinfo(&ctx(&f), &t).await.is_err(),
        "userinfo is a server error"
    );

    let client = f
        .clients
        .clients
        .iter()
        .find(|c| c.client_id == "web")
        .unwrap()
        .clone();
    let resources =
        validate_requested_resources(&client, &f.resources.enabled(), &["openid".to_owned()], &[])
            .unwrap();
    let issued = Issuer {
        options: &f.options,
        stores: &f.stores,
        keys: &f.keys,
        issuer: ISSUER,
        now: chrono::Utc::now(),
    }
    .identity_token(&client, &resources, &session(), &Default::default())
    .await;
    assert!(
        matches!(issued, Err(rustid_core::token::TokenFailure::Server(_))),
        "{issued:?}"
    );
}

fn asking_for(alg: Option<&str>, pairwise: bool) -> Fixture {
    let mut f = Fixture::new();
    if pairwise {
        f.options.pairwise.salt = Some("server-salt-0123456789".into());
    }
    f.edit_clients(|clients| {
        for c in clients.iter_mut().filter(|c| c.client_id == "web") {
            c.userinfo_signed_response_alg = alg.map(str::to_owned);
            if pairwise {
                c.subject_type = rustid_core::clients::SubjectType::Pairwise;
            }
        }
    });
    f
}

#[tokio::test]
async fn a_client_that_asks_gets_a_signed_answer() {
    use rustid_core::userinfo::{UserInfoAnswer, userinfo_response};
    let f = asking_for(Some("RS256"), false);
    let t = token(&f, &["openid", "profile", "api1"], chrono::Utc::now()).await;
    let UserInfoAnswer::Jwt(jwt) = userinfo_response(&ctx(&f), &t).await.unwrap().unwrap() else {
        panic!("a JWT");
    };
    let jws = rustid_core::jwt::Jws::decode(&jwt).unwrap();
    assert_eq!(jws.header_str("alg"), Some("RS256"));
    let key = f.material.signing.first().unwrap();
    assert!(jws.verify(&key.public_jwk()));
    assert_eq!(jws.payload["iss"], ISSUER);
    assert_eq!(jws.payload["aud"], "web");
    assert_eq!(jws.payload["sub"], "1");
    assert_eq!(jws.payload["name"], "Alice");
}

#[tokio::test]
async fn a_client_that_doesnt_ask_gets_json() {
    use rustid_core::userinfo::{UserInfoAnswer, userinfo_response};
    let f = asking_for(None, false);
    let t = token(&f, &["openid", "profile", "api1"], chrono::Utc::now()).await;
    let UserInfoAnswer::Json(claims) = userinfo_response(&ctx(&f), &t).await.unwrap().unwrap()
    else {
        panic!("JSON");
    };
    assert_eq!(
        serde_json::Value::Object(claims),
        serde_json::json!({ "name": "Alice", "sub": "1" })
    );
}

#[tokio::test]
async fn a_signed_answer_keeps_the_pairwise_subject() {
    use rustid_core::userinfo::{UserInfoAnswer, userinfo_response};
    let f = asking_for(Some("RS256"), true);
    let t = token(&f, &["openid", "api1"], chrono::Utc::now()).await;
    let UserInfoAnswer::Jwt(jwt) = userinfo_response(&ctx(&f), &t).await.unwrap().unwrap() else {
        panic!("a JWT");
    };
    let sub = rustid_core::jwt::Jws::decode(&jwt).unwrap().payload["sub"].clone();
    assert_ne!(sub, "1");
}

#[tokio::test]
async fn no_key_for_the_algorithm_is_a_server_error_never_unsigned() {
    use rustid_core::userinfo::userinfo_response;
    let f = asking_for(Some("ES256"), false);
    let t = token(&f, &["openid", "api1"], chrono::Utc::now()).await;
    assert!(userinfo_response(&ctx(&f), &t).await.is_err());
}
