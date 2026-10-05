//! Signing in through an upstream provider: the challenge that sends the
//! browser upstream, the callback that checks what comes back and signs
//! the user in through a continuation, and the ways a callback fails.

use axum::http::{Method, StatusCode};
use rustid_core::federation::session::subject_for;

mod browser;

use browser::upstream::*;
use browser::*;

fn authorize_for(client_id: &str, extra: &str) -> String {
    authorize_uri(extra).replace("client_id=web", &format!("client_id={client_id}"))
}

fn encode(value: &str) -> String {
    rustid_core::params::url_encode(value)
}

/// The authorize request's return URL (from the login page redirect) and
/// the upstream URL the challenge redirects to.
async fn start(browser: &mut Browser) -> (String, String) {
    let login = browser.get(&authorize_for("fed.client", "")).await;
    let return_url = return_url(&login.location());
    let upstream = challenge(browser, &return_url).await;
    (return_url, upstream)
}

async fn challenge(browser: &mut Browser, return_url: &str) -> String {
    let reply = browser
        .get(&format!(
            "/federation/up/challenge?returnUrl={}",
            encode(return_url)
        ))
        .await;
    assert_eq!(reply.status, StatusCode::FOUND, "{}", reply.body);
    reply.location()
}

/// The callback for `upstream` (the URL the challenge sent the browser to)
/// with a code, after telling the fake which nonce to sign.
async fn callback(f: &Federated, browser: &mut Browser, upstream: &str) -> Reply {
    f.fake.expect_nonce(&query(upstream, "nonce").unwrap());
    let state = query(upstream, "state").unwrap();
    browser
        .get(&format!(
            "/federation/up/callback?code=c1&state={}",
            encode(&state)
        ))
        .await
}

async fn session(browser: &mut Browser) -> serde_json::Value {
    let bearer = format!("Bearer {API_KEY}");
    let reply = browser
        .send(
            Method::GET,
            "/interaction/session",
            &[("authorization", &bearer)],
            "",
        )
        .await;
    serde_json::from_str(&reply.body).unwrap()
}

#[tokio::test]
async fn challenge_redirects_upstream_with_pkce_and_sets_the_cookie() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let login = b
        .get(&authorize_for("fed.client", "&login_hint=ada%40x"))
        .await;
    let return_url = return_url(&login.location());
    let reply = b
        .get(&format!(
            "/federation/up/challenge?returnUrl={}",
            encode(&return_url)
        ))
        .await;
    assert_eq!(reply.status, StatusCode::FOUND);
    let upstream = reply.location();
    assert!(
        upstream.starts_with("https://up.example/authorize?"),
        "{upstream}"
    );
    assert_eq!(
        query(&upstream, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert_eq!(
        query(&upstream, "redirect_uri").as_deref(),
        Some("https://idsrv.test/federation/up/callback")
    );
    assert_eq!(query(&upstream, "client_id").as_deref(), Some("rustid"));
    assert_eq!(query(&upstream, "login_hint").as_deref(), Some("ada@x"));
    let cookie = reply
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("idsrv.federation="))
        .unwrap();
    assert!(
        cookie.ends_with("; path=/federation/up/; max-age=600; samesite=lax; httponly"),
        "{cookie}"
    );
}

#[tokio::test]
async fn full_sign_in() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let (return_url, upstream) = start(&mut b).await;
    let reply = callback(&f, &mut b, &upstream).await;
    assert_eq!(reply.status, StatusCode::FOUND, "{}", reply.body);
    let continue_url = reply.location();
    assert!(
        continue_url.starts_with("http://server/connect/interaction/continue?token="),
        "{continue_url}"
    );
    let signed_in = b
        .get(continue_url.strip_prefix("http://server").unwrap())
        .await;
    assert_eq!(signed_in.status, StatusCode::FOUND, "{}", signed_in.body);
    assert_eq!(signed_in.location(), return_url);
    let s = session(&mut b).await;
    assert_eq!(s["subjectId"], subject_for(AUTHORITY, "upstream-user"));
    assert_eq!(s["idp"], "up");
    assert_eq!(s["amr"], serde_json::json!(["external"]));
    let claims: Vec<&str> = s["claims"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["type"].as_str().unwrap())
        .collect();
    assert!(
        claims.contains(&"name") && claims.contains(&"email"),
        "{claims:?}"
    );
    // The authorize request now completes: a code for the client.
    let done = b.get(&return_url).await;
    assert!(
        done.location()
            .starts_with("https://client.test/callback?code="),
        "{}",
        done.location()
    );
    let success = f.events.named("User Login Success");
    assert_eq!(success.len(), 1);
    assert_eq!(success[0]["Provider"], "up");
    assert_eq!(success[0]["ProviderUserId"], "upstream-user");
    assert_eq!(success[0]["ClientId"], "fed.client");
    // The token request carried the PKCE verifier and Basic credentials.
    let posts = &f.fake.state.lock().unwrap().posts;
    assert!(posts[0].form.iter().any(|(k, _)| k == "code_verifier"));
    assert_eq!(posts[0].basic, Some(("rustid".into(), "secret".into())));
}

#[tokio::test]
async fn callback_without_cookie_is_expired() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let (_, upstream) = start(&mut b).await;
    b.drop_cookie("idsrv.federation");
    let reply = callback(&f, &mut b, &upstream).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert!(reply.body.contains("expired"), "{}", reply.body);
    let failure = f.events.named("User Login Failure");
    assert_eq!(failure[0]["Reason"], "expired");
}

#[tokio::test]
async fn replayed_callback_is_expired() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let (_, upstream) = start(&mut b).await;
    let first = callback(&f, &mut b, &upstream).await;
    assert_eq!(first.status, StatusCode::FOUND);
    let again = callback(&f, &mut b, &upstream).await;
    assert_eq!(again.status, StatusCode::BAD_REQUEST);
    assert!(again.body.contains("expired"));
}

#[tokio::test]
async fn state_mismatch_is_400() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    start(&mut b).await;
    let reply = b.get("/federation/up/callback?code=c1&state=wrong").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        f.events.named("User Login Failure")[0]["Reason"],
        "state_mismatch"
    );
}

#[tokio::test]
async fn second_challenge_replaces_the_first() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let (return_url, first) = start(&mut b).await;
    let _second = challenge(&mut b, &return_url).await;
    let reply = callback(&f, &mut b, &first).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        f.events.named("User Login Failure")[0]["Reason"],
        "state_mismatch"
    );
}

#[tokio::test]
async fn issuer_parameter_must_match() {
    let f = federated();
    f.fake
        .edit(|s| s.discovery["authorization_response_iss_parameter_supported"] = true.into());
    let mut b = Browser::new(&f.app);
    let (_, upstream) = start(&mut b).await;
    let state = query(&upstream, "state").unwrap();
    let missing = b
        .get(&format!(
            "/federation/up/callback?code=c1&state={}",
            encode(&state)
        ))
        .await;
    assert_eq!(missing.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        f.events.named("User Login Failure")[0]["Reason"],
        "issuer_mismatch"
    );

    let (_, upstream) = start(&mut b).await;
    let state = query(&upstream, "state").unwrap();
    let evil = b
        .get(&format!(
            "/federation/up/callback?code=c1&state={}&iss=https%3A%2F%2Fevil",
            encode(&state)
        ))
        .await;
    assert_eq!(evil.status, StatusCode::BAD_REQUEST);

    let (_, upstream) = start(&mut b).await;
    f.fake.expect_nonce(&query(&upstream, "nonce").unwrap());
    let state = query(&upstream, "state").unwrap();
    let good = b
        .get(&format!(
            "/federation/up/callback?code=c1&state={}&iss={}",
            encode(&state),
            encode(AUTHORITY)
        ))
        .await;
    assert_eq!(good.status, StatusCode::FOUND, "{}", good.body);
}

#[tokio::test]
async fn access_denied_denies_the_request() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let (return_url, upstream) = start(&mut b).await;
    let state = query(&upstream, "state").unwrap();
    let reply = b
        .get(&format!(
            "/federation/up/callback?error=access_denied&state={}",
            encode(&state)
        ))
        .await;
    assert_eq!(reply.status, StatusCode::FOUND, "{}", reply.body);
    assert_eq!(reply.location(), format!("http://server{return_url}"));
    let answered = b.get(&return_url).await;
    assert!(
        answered
            .location()
            .starts_with("https://client.test/callback?error=access_denied"),
        "{}",
        answered.location()
    );
}

#[tokio::test]
async fn other_upstream_error_is_502() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let (_, upstream) = start(&mut b).await;
    let state = query(&upstream, "state").unwrap();
    let reply = b
        .get(&format!(
            "/federation/up/callback?error=server_error&error_description=secret%20detail&state={}",
            encode(&state)
        ))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert!(!reply.body.contains("secret detail"));
    let failure = &f.events.named("User Login Failure")[0];
    assert_eq!(failure["Reason"], "upstream_error");
    assert!(failure["Detail"].as_str().unwrap().contains("server_error"));
}

#[tokio::test]
async fn bad_id_token_is_502_and_records_the_check() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let (_, upstream) = start(&mut b).await;
    let state = query(&upstream, "state").unwrap();
    f.fake.expect_nonce("wrong");
    let reply = b
        .get(&format!(
            "/federation/up/callback?code=c1&state={}",
            encode(&state)
        ))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    let failure = &f.events.named("User Login Failure")[0];
    assert_eq!(failure["Reason"], "id_token_invalid");
    assert!(failure["Detail"].as_str().unwrap().contains("nonce"));
}

#[tokio::test]
async fn token_endpoint_failure_is_502() {
    let f = federated();
    f.fake.edit(|s| s.token_status = 400);
    let mut b = Browser::new(&f.app);
    let (_, upstream) = start(&mut b).await;
    let reply = callback(&f, &mut b, &upstream).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        f.events.named("User Login Failure")[0]["Reason"],
        "token_request_failed"
    );
}

#[tokio::test]
async fn unavailable_metadata_is_502_at_the_challenge() {
    let f = federated();
    f.fake
        .edit(|s| s.discovery["issuer"] = "https://other.example".into());
    let mut b = Browser::new(&f.app);
    let login = b.get(&authorize_for("fed.client", "")).await;
    let return_url = return_url(&login.location());
    let reply = b
        .get(&format!(
            "/federation/up/challenge?returnUrl={}",
            encode(&return_url)
        ))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        f.events.named("User Login Failure")[0]["Reason"],
        "metadata_unavailable"
    );
}

#[tokio::test]
async fn unknown_and_disabled_providers_are_404() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let login = b.get(&authorize_for("fed.client", "")).await;
    let return_url = encode(&return_url(&login.location()));
    for scheme in ["nope", "off"] {
        let reply = b
            .get(&format!(
                "/federation/{scheme}/challenge?returnUrl={return_url}"
            ))
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{scheme}");
        let reply = b
            .get(&format!("/federation/{scheme}/callback?code=c&state=s"))
            .await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{scheme}");
    }
}

#[tokio::test]
async fn challenge_refuses_bad_return_urls_and_disallowed_clients() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    for bad in [
        "",
        "https%3A%2F%2Fevil%2Fconnect%2Fauthorize%2Fcallback",
        "%2Fnot-a-callback",
    ] {
        let reply = b
            .get(&format!("/federation/up/challenge?returnUrl={bad}"))
            .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let login = b.get(&authorize_for("fed.other", "")).await;
    let return_url = return_url(&login.location());
    let reply = b
        .get(&format!(
            "/federation/up/challenge?returnUrl={}",
            encode(&return_url)
        ))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn only_get_is_allowed() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let reply = b
        .send(Method::POST, "/federation/up/callback", &[], "")
        .await;
    assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn absolute_return_url_round_trips() {
    let mut options = rustid_core::options::ProtocolOptions::default();
    options.user_interaction.login_url = "https://ui.example/login".into();
    let f = federated_with(options);
    let mut b = Browser::new(&f.app);
    let login = b.get(&authorize_for("fed.client", "")).await;
    let return_url = return_url(&login.location());
    assert!(return_url.starts_with("http://server/"), "{return_url}");
    let upstream = challenge(&mut b, &return_url).await;
    let reply = callback(&f, &mut b, &upstream).await;
    assert_eq!(reply.status, StatusCode::FOUND, "{}", reply.body);
    let signed_in = b
        .get(reply.location().strip_prefix("http://server").unwrap())
        .await;
    assert_eq!(signed_in.status, StatusCode::FOUND, "{}", signed_in.body);
    assert_eq!(session(&mut b).await["idp"], "up");
}

#[tokio::test]
async fn continuation_requires_the_same_browser() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let (_, upstream) = start(&mut b).await;
    let reply = callback(&f, &mut b, &upstream).await;
    let mut other = Browser::new(&f.app);
    let stolen = other
        .get(reply.location().strip_prefix("http://server").unwrap())
        .await;
    assert_eq!(stolen.status, StatusCode::BAD_REQUEST);
    assert!(stolen.body.contains("invalid_continuation"));
}
