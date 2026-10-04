//! JARM responses end to end: the parameters arrive as one signed JWT in
//! `response`, by query, fragment or auto-posted form; safe errors too.

mod browser;

use axum::http::StatusCode;
use browser::*;
use rustid_core::jwt::{Jws, PublicJwk};

fn jarm_state() -> rustid_http::AppState {
    let mut options = rustid_core::options::ProtocolOptions::default();
    options.jarm.enabled = true;
    state_with(options)
}

/// The `response` parameter of a redirect's query or fragment, checking it
/// is the only parameter.
fn only_response(location: &str, fragment: bool) -> String {
    let url = url::Url::parse(location).unwrap();
    let part = if fragment {
        url.fragment().unwrap_or_default().to_owned()
    } else {
        url.query().unwrap_or_default().to_owned()
    };
    let pairs: Vec<(String, String)> = url::form_urlencoded::parse(part.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(pairs.len(), 1, "only `response`: {location}");
    assert_eq!(pairs[0].0, "response");
    pairs[0].1.clone()
}

/// The JWT, verified with the key the JWKS publishes for its `kid`.
async fn verified(browser: &mut Browser, jwt: &str) -> Jws {
    let jws = Jws::decode(jwt).unwrap();
    let kid = jws.header_str("kid").unwrap().to_owned();
    let jwks: serde_json::Value = serde_json::from_str(
        &browser
            .get("/.well-known/openid-configuration/jwks")
            .await
            .body,
    )
    .unwrap();
    let jwk = jwks["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["kid"] == kid.as_str())
        .unwrap_or_else(|| panic!("{kid} is not published"));
    assert!(jws.verify(&PublicJwk::parse(&jwk.to_string()).unwrap()));
    jws
}

fn assert_claims(jws: &Jws) {
    let now = chrono::Utc::now().timestamp();
    assert_eq!(jws.claim_str("iss"), Some("https://idsrv.test"));
    assert_eq!(jws.payload["aud"], serde_json::json!("web"));
    let exp = jws.claim_i64("exp").unwrap();
    assert!(exp >= now + 10 && exp <= now + 600, "exp {exp}, now {now}");
}

#[tokio::test]
async fn a_code_response_is_a_signed_jarm_jwt() {
    let app = jarm_state();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let r = browser.get(&authorize_uri("&response_mode=jwt")).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let location = r.location();
    assert!(
        location.starts_with("https://client.test/callback?response="),
        "{location}"
    );
    let jwt = only_response(&location, false);
    let jws = verified(&mut browser, &jwt).await;
    assert_claims(&jws);
    assert!(jws.claim_str("code").is_some());
    assert_eq!(jws.claim_str("state"), Some("s1"));
    assert!(jws.claim_str("session_state").is_some());
}

#[tokio::test]
async fn form_post_jwt_posts_one_response_field() {
    let app = jarm_state();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let r = browser
        .get(&authorize_uri("&response_mode=form_post.jwt"))
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.headers.contains_key("content-security-policy"));
    assert_eq!(r.body.matches("type='hidden'").count(), 1, "{}", r.body);
    let start = r.body.find("name='response' value='").unwrap() + "name='response' value='".len();
    let jwt = &r.body[start..start + r.body[start..].find('\'').unwrap()];
    let jws = verified(&mut browser, jwt).await;
    assert_claims(&jws);
}

#[tokio::test]
async fn fragment_jwt_for_hybrid() {
    let app = jarm_state();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let uri = "/connect/authorize?client_id=hybrid&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code%20id_token&scope=openid&state=s1&nonce=n1&response_mode=jwt";
    let r = browser.get(uri).await;
    let location = r.location();
    assert!(
        location.starts_with("https://client.test/callback#response="),
        "{location}"
    );
    let jws = verified(&mut browser, &only_response(&location, true)).await;
    assert_eq!(jws.payload["aud"], serde_json::json!("hybrid"));
    assert!(jws.claim_str("code").is_some() && jws.claim_str("id_token").is_some());
}

#[tokio::test]
async fn a_safe_error_is_a_jarm_jwt() {
    let app = jarm_state();
    let mut browser = Browser::new(&app);
    let r = browser
        .get(&authorize_uri("&response_mode=jwt&prompt=none"))
        .await;
    let location = r.location();
    assert!(!location.ends_with("#_"), "{location}");
    let jws = verified(&mut browser, &only_response(&location, false)).await;
    assert_claims(&jws);
    assert_eq!(jws.claim_str("error"), Some("login_required"));
    assert_eq!(jws.claim_str("state"), Some("s1"));
}

#[tokio::test]
async fn unsafe_errors_still_show_the_error_page() {
    let app = jarm_state();
    let mut browser = Browser::new(&app);
    let r = browser
        .get(
            &authorize_uri("&response_mode=jwt")
                .replace("client.test%2Fcallback", "evil.test%2Fcallback"),
        )
        .await;
    assert!(r.location().contains("/home/error"), "{}", r.location());
}

/// A JARM response the client's algorithms can't sign: a 500 before any
/// code is stored.
#[tokio::test]
async fn no_jarm_key_stores_no_code() {
    let mut options = rustid_core::options::ProtocolOptions::default();
    options.jarm.enabled = true;
    let mut clients = rustid_core::clients::Clients::load(&fixture("clients.json")).unwrap();
    for client in &mut clients.clients {
        if client.client_id == "web" {
            client.allowed_identity_token_signing_algorithms = vec!["ES256".into()];
        }
    }
    let resources = rustid_core::resources::Resources::load(&fixture("resources.json")).unwrap();
    let app = rustid_http::AppState::new(rustid_http::ProtocolState {
        stores: rustid_store_memory::stores(clients, resources),
        ..protocol_state_with(options)
    });
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let r = browser
        .get(&authorize_uri("&response_mode=query.jwt"))
        .await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR);
    let codes = app
        .0
        .stores
        .grants
        .get_all(&rustid_core::grants::GrantFilter {
            subject_id: Some("1".into()),
            grant_type: Some("authorization_code".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(codes.is_empty(), "no code stored: {codes:?}");
}
