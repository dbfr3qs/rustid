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

async fn login_context(browser: &mut Browser, return_url: &str) -> serde_json::Value {
    let bearer = format!("Bearer {API_KEY}");
    let mut ui = Browser::new(&browser.app);
    let reply = ui
        .send(
            Method::GET,
            &format!("/interaction/login?returnUrl={}", encode(return_url)),
            &[("authorization", &bearer)],
            "",
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    serde_json::from_str(&reply.body).unwrap()
}

#[tokio::test]
async fn login_context_lists_allowed_providers() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let login = b.get(&authorize_for("fed.client", "")).await;
    let return_url = return_url(&login.location());
    let context = login_context(&mut b, &return_url).await;
    assert_eq!(context["enableLocalLogin"], true);
    assert_eq!(
        context["identityProviders"],
        serde_json::json!([{
            "scheme": "up",
            "displayName": "Upstream",
            "challengeUrl": format!("http://server/federation/up/challenge?returnUrl={}", encode(&return_url)),
        }])
    );
    // The challenge URL works as it is.
    let challenge_url = context["identityProviders"][0]["challengeUrl"]
        .as_str()
        .unwrap();
    let reply = b
        .get(challenge_url.strip_prefix("http://server").unwrap())
        .await;
    assert_eq!(reply.status, StatusCode::FOUND);
    assert!(
        reply
            .location()
            .starts_with("https://up.example/authorize?")
    );
}

#[tokio::test]
async fn idp_hint_skips_the_login_page() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let reply = b
        .get(&authorize_for("fed.client", "&acr_values=idp%3Aup"))
        .await;
    let location = reply.location();
    assert!(
        location.starts_with("http://server/federation/up/challenge?returnUrl="),
        "{location}"
    );
    assert!(
        reply.cookie("idsrv.interaction").is_some(),
        "the interaction is bound to the browser"
    );
    let upstream = b.get(location.strip_prefix("http://server").unwrap()).await;
    assert_eq!(upstream.status, StatusCode::FOUND);
    // The whole sign-in completes from here.
    let reply = callback(&f, &mut b, &upstream.location()).await;
    let signed_in = b
        .get(reply.location().strip_prefix("http://server").unwrap())
        .await;
    assert_eq!(signed_in.status, StatusCode::FOUND, "{}", signed_in.body);
}

#[tokio::test]
async fn idp_local_keeps_the_login_page() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let reply = b
        .get(&authorize_for("fed.client", "&acr_values=idp%3Alocal"))
        .await;
    assert!(
        reply.location().contains("/Account/Login"),
        "{}",
        reply.location()
    );
}

#[tokio::test]
async fn single_provider_client_goes_straight_upstream() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let reply = b.get(&authorize_for("fed.only", "")).await;
    assert!(
        reply
            .location()
            .starts_with("http://server/federation/up/challenge?returnUrl="),
        "{}",
        reply.location()
    );
}

#[tokio::test]
async fn unknown_restriction_falls_back_to_login_page() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let reply = b.get(&authorize_for("fed.missing", "")).await;
    assert!(
        reply.location().contains("/Account/Login"),
        "{}",
        reply.location()
    );
    let context = login_context(&mut b, &return_url(&reply.location())).await;
    assert_eq!(context["identityProviders"], serde_json::json!([]));
    assert_eq!(context["enableLocalLogin"], false);
}

#[tokio::test]
async fn prompt_none_still_errors() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let reply = b.get(&authorize_for("fed.only", "&prompt=none")).await;
    assert!(
        reply
            .location()
            .starts_with("https://client.test/callback?error=login_required"),
        "{}",
        reply.location()
    );
}

#[tokio::test]
async fn prompt_login_and_max_age_reach_the_provider() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let login = b
        .get(&authorize_for("fed.client", "&prompt=login&max_age=0"))
        .await;
    let return_url = return_url(&login.location());
    let upstream = challenge(&mut b, &return_url).await;
    assert_eq!(
        query(&upstream, "prompt").as_deref(),
        Some("login"),
        "{upstream}"
    );
    assert_eq!(
        query(&upstream, "max_age").as_deref(),
        Some("0"),
        "{upstream}"
    );
    // Straight upstream through the idp hint too.
    let hinted = b
        .get(&authorize_for(
            "fed.client",
            "&prompt=login&max_age=30&acr_values=idp%3Aup",
        ))
        .await;
    let upstream = b
        .get(hinted.location().strip_prefix("http://server").unwrap())
        .await
        .location();
    assert_eq!(query(&upstream, "prompt").as_deref(), Some("login"));
    assert_eq!(query(&upstream, "max_age").as_deref(), Some("30"));
}

#[tokio::test]
async fn stale_upstream_authentication_is_refused() {
    let f = federated();
    let mut b = Browser::new(&f.app);
    let now = chrono::Utc::now().timestamp();
    for (auth_time, expected) in [
        (Some(now - 3600), StatusCode::BAD_GATEWAY),
        (None, StatusCode::BAD_GATEWAY),
        (Some(now - 5), StatusCode::FOUND),
    ] {
        f.fake.edit(|s| match auth_time {
            Some(t) => s.claims["auth_time"] = t.into(),
            None => {
                s.claims.as_object_mut().unwrap().remove("auth_time");
            }
        });
        let login = b.get(&authorize_for("fed.client", "&max_age=60")).await;
        let return_url = return_url(&login.location());
        let upstream = challenge(&mut b, &return_url).await;
        let reply = callback(&f, &mut b, &upstream).await;
        assert_eq!(
            reply.status, expected,
            "auth_time {auth_time:?}: {}",
            reply.body
        );
    }
    let reasons: Vec<serde_json::Value> = f
        .events
        .named("User Login Failure")
        .iter()
        .map(|e| e["Reason"].clone())
        .collect();
    assert_eq!(reasons, ["stale_authentication", "stale_authentication"]);
}

/// Signs in through `up` and returns the signed-in browser's state.
async fn signed_in_upstream(f: &Federated, b: &mut Browser) {
    let (_, upstream) = start(b).await;
    let reply = callback(f, b, &upstream).await;
    let signed_in = b
        .get(reply.location().strip_prefix("http://server").unwrap())
        .await;
    assert_eq!(signed_in.status, StatusCode::FOUND, "{}", signed_in.body);
}

/// The UI's logout call and its continuation, returning the continuation's
/// answer.
async fn sign_out(b: &mut Browser) -> Reply {
    sign_out_to(b, "/signed-out?x=1").await
}

async fn sign_out_to(b: &mut Browser, return_url: &str) -> Reply {
    let bearer = format!("Bearer {API_KEY}");
    let cookie: Vec<String> = b.cookies.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut ui = Browser::new(&b.app);
    let reply = ui
        .send(
            Method::POST,
            "/interaction/logout",
            &[
                ("authorization", &bearer),
                ("content-type", "application/json"),
                ("cookie", &cookie.join("; ")),
            ],
            &serde_json::json!({ "returnUrl": return_url }).to_string(),
        )
        .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let path = body["continueUrl"]
        .as_str()
        .unwrap()
        .strip_prefix("http://server")
        .unwrap()
        .to_owned();
    b.get(&path).await
}

fn sign_out_on(p: &mut rustid_core::federation::provider::IdentityProvider) {
    p.sign_out = true;
}

#[tokio::test]
async fn sign_out_goes_upstream_and_returns() {
    let f = federated_custom(Default::default(), sign_out_on, true);
    let mut b = Browser::new(&f.app);
    signed_in_upstream(&f, &mut b).await;
    let reply = sign_out(&mut b).await;
    assert_eq!(reply.status, StatusCode::FOUND, "{}", reply.body);
    let upstream = reply.location();
    assert!(
        upstream.starts_with("https://up.example/endsession?"),
        "{upstream}"
    );
    let hint = query(&upstream, "id_token_hint").expect("the upstream token is the hint");
    assert_eq!(
        rustid_core::jwt::Jws::decode(&hint)
            .unwrap()
            .claim_str("sub"),
        Some("upstream-user")
    );
    assert_eq!(query(&upstream, "client_id").as_deref(), Some("rustid"));
    assert_eq!(
        query(&upstream, "post_logout_redirect_uri").as_deref(),
        Some("https://idsrv.test/federation/up/signout-callback")
    );
    let state = query(&upstream, "state").unwrap();
    let cookies = reply.set_cookies();
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("idsrv.federation.signout=")),
        "{cookies:?}"
    );
    assert!(
        cookies.iter().any(|c| c.starts_with("idsrv=;")),
        "the session cookie goes: {cookies:?}"
    );
    // Back from the provider: on to the UI's return URL.
    let back = b
        .get(&format!(
            "/federation/up/signout-callback?state={}",
            encode(&state)
        ))
        .await;
    assert_eq!(back.status, StatusCode::FOUND, "{}", back.body);
    assert_eq!(back.location(), "/signed-out?x=1");
    assert!(
        back.set_cookies()
            .iter()
            .any(|c| c.starts_with("idsrv.federation.signout=;"))
    );
    assert_eq!(session(&mut b).await["error"], "no_session");
}

#[tokio::test]
async fn signout_callback_state_is_checked() {
    let f = federated_custom(Default::default(), sign_out_on, true);
    let mut b = Browser::new(&f.app);
    signed_in_upstream(&f, &mut b).await;
    let upstream = sign_out(&mut b).await.location();
    let state = query(&upstream, "state").unwrap();
    for (label, path) in [
        (
            "wrong state",
            "/federation/up/signout-callback?state=wrong".to_owned(),
        ),
        ("no state", "/federation/up/signout-callback".to_owned()),
    ] {
        let reply = b.get(&path).await;
        assert_eq!(reply.status, StatusCode::OK, "{label}");
        assert!(reply.body.contains("signed out"), "{label}: {}", reply.body);
    }
    // The cookie went with the first visit: the real state no longer works.
    let replay = b
        .get(&format!(
            "/federation/up/signout-callback?state={}",
            encode(&state)
        ))
        .await;
    assert_eq!(replay.status, StatusCode::OK);
}

#[tokio::test]
async fn without_server_side_sessions_only_client_id_is_sent() {
    let f = federated_custom(Default::default(), sign_out_on, false);
    let mut b = Browser::new(&f.app);
    signed_in_upstream(&f, &mut b).await;
    let upstream = sign_out(&mut b).await.location();
    assert!(
        upstream.starts_with("https://up.example/endsession?"),
        "{upstream}"
    );
    assert_eq!(query(&upstream, "id_token_hint"), None);
    assert_eq!(query(&upstream, "client_id").as_deref(), Some("rustid"));
}

#[tokio::test]
async fn provider_without_end_session_endpoint_signs_out_locally() {
    let f = federated_custom(Default::default(), sign_out_on, true);
    f.fake.edit(|s| {
        s.discovery
            .as_object_mut()
            .unwrap()
            .remove("end_session_endpoint");
    });
    let mut b = Browser::new(&f.app);
    signed_in_upstream(&f, &mut b).await;
    let reply = sign_out(&mut b).await;
    assert_eq!(reply.status, StatusCode::FOUND);
    assert_eq!(reply.location(), "/signed-out?x=1");
    assert_eq!(session(&mut b).await["error"], "no_session");
}

#[tokio::test]
async fn provider_without_sign_out_signs_out_locally() {
    let f = federated_custom(Default::default(), |_| {}, true);
    let mut b = Browser::new(&f.app);
    signed_in_upstream(&f, &mut b).await;
    let reply = sign_out(&mut b).await;
    assert_eq!(reply.status, StatusCode::FOUND);
    assert_eq!(reply.location(), "/signed-out?x=1");
    assert_eq!(session(&mut b).await["error"], "no_session");
}

#[tokio::test]
async fn local_session_sign_out_is_unchanged() {
    let f = federated_custom(Default::default(), sign_out_on, true);
    let mut b = Browser::new(&f.app);
    sign_in(&mut b, "alice").await;
    let reply = sign_out(&mut b).await;
    assert_eq!(reply.status, StatusCode::FOUND);
    assert_eq!(reply.location(), "/signed-out?x=1");
}

#[tokio::test]
async fn a_long_return_url_keeps_the_signout_cookie_small() {
    let f = federated_custom(Default::default(), sign_out_on, true);
    let mut b = Browser::new(&f.app);
    signed_in_upstream(&f, &mut b).await;
    let long = format!("/signed-out?logoutId={}", "x".repeat(6000));
    let reply = sign_out_to(&mut b, &long).await;
    let cookie = reply
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with("idsrv.federation.signout="))
        .unwrap();
    assert!(cookie.len() < 1024, "{} bytes", cookie.len());
    let state = query(&reply.location(), "state").unwrap();
    let back = b
        .get(&format!(
            "/federation/up/signout-callback?state={}",
            encode(&state)
        ))
        .await;
    assert_eq!(back.status, StatusCode::FOUND);
    assert_eq!(back.location(), long);
}

const TENANT: &str = "11111111-1111-1111-1111-111111111111";

fn entra(p: &mut rustid_core::federation::provider::IdentityProvider) {
    p.authority = "https://up.example/organizations/v2.0".into();
    p.multi_tenant = Some(rustid_core::federation::provider::MultiTenant {
        tenants: vec![TENANT.into()],
    });
}

fn tenant(f: &Federated, tid: &str) {
    f.fake.edit(|s| {
        s.discovery["issuer"] = "https://up.example/{tenantid}/v2.0".into();
        s.claims["iss"] = format!("https://up.example/{tid}/v2.0").into();
        s.claims["tid"] = tid.into();
    });
}

#[tokio::test]
async fn multi_tenant_sign_in_end_to_end() {
    let f = federated_custom(Default::default(), entra, false);
    tenant(&f, TENANT);
    let mut b = Browser::new(&f.app);
    signed_in_upstream(&f, &mut b).await;
    let s = session(&mut b).await;
    assert_eq!(
        s["subjectId"],
        subject_for(
            &format!("https://up.example/{TENANT}/v2.0"),
            "upstream-user"
        )
    );
    assert_eq!(s["idp"], "up");
}

#[tokio::test]
async fn tenant_not_allowed_is_502() {
    let f = federated_custom(Default::default(), entra, false);
    tenant(&f, "22222222-2222-2222-2222-222222222222");
    let mut b = Browser::new(&f.app);
    let (_, upstream) = start(&mut b).await;
    let reply = callback(&f, &mut b, &upstream).await;
    assert_eq!(reply.status, StatusCode::BAD_GATEWAY);
    let failure = &f.events.named("User Login Failure")[0];
    assert_eq!(failure["Reason"], "tenant_not_allowed");
}

#[tokio::test]
async fn multi_tenant_callbacks_accept_a_tenant_issuer_that_matches_the_token() {
    const OTHER: &str = "22222222-2222-2222-2222-222222222222";
    let f = federated_custom(
        Default::default(),
        |p| {
            entra(p);
            p.multi_tenant.as_mut().unwrap().tenants.push(OTHER.into());
        },
        false,
    );
    tenant(&f, TENANT);
    f.fake
        .edit(|s| s.discovery["authorization_response_iss_parameter_supported"] = true.into());
    let mut b = Browser::new(&f.app);
    let with_iss = |upstream: &str, iss: &str| {
        format!(
            "/federation/up/callback?code=c1&state={}&iss={}",
            encode(&query(upstream, "state").unwrap()),
            encode(iss)
        )
    };
    let tenant_issuer = |t: &str| format!("https://up.example/{t}/v2.0");

    // The token's tenant's issuer: signed in.
    let (_, upstream) = start(&mut b).await;
    f.fake.expect_nonce(&query(&upstream, "nonce").unwrap());
    let reply = b.get(&with_iss(&upstream, &tenant_issuer(TENANT))).await;
    assert_eq!(reply.status, StatusCode::FOUND, "{}", reply.body);

    // A tenant that isn't listed: refused before the code is redeemed.
    let (_, upstream) = start(&mut b).await;
    let reply = b
        .get(&with_iss(
            &upstream,
            &tenant_issuer("33333333-3333-3333-3333-333333333333"),
        ))
        .await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);

    // Another listed tenant than the token's: refused once the token says so.
    let (_, upstream) = start(&mut b).await;
    f.fake.expect_nonce(&query(&upstream, "nonce").unwrap());
    let reply = b.get(&with_iss(&upstream, &tenant_issuer(OTHER))).await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    let reasons: Vec<serde_json::Value> = f
        .events
        .named("User Login Failure")
        .iter()
        .map(|e| e["Reason"].clone())
        .collect();
    assert_eq!(reasons, ["issuer_mismatch", "issuer_mismatch"]);
}

#[tokio::test]
async fn providers_managed_through_admin_take_effect_at_once() {
    use rustid_core::admin::identity_providers::{IdentityProviderAdmin, IdentityProviderInput};
    let (f, configuration, protector) = federated_from_store();
    let admin = IdentityProviderAdmin::new(protector);
    let mut b = Browser::new(&f.app);
    let login = b.get(&authorize_for("fed.client", "")).await;
    let first = return_url(&login.location());
    // No provider yet.
    let none = b
        .get(&format!(
            "/federation/up/challenge?returnUrl={}",
            encode(&first)
        ))
        .await;
    assert_eq!(none.status, StatusCode::NOT_FOUND);

    let provider = serde_json::json!({
        "scheme": "up", "displayName": "Upstream", "authority": AUTHORITY,
        "clientId": "rustid", "clientAuthentication": { "secret": "secret" },
    });
    let saved = admin
        .create(
            configuration.as_ref(),
            IdentityProviderInput::from_json(provider.clone()).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    // Usable at once: a full sign-in, with the secret from the store.
    signed_in_upstream(&f, &mut b).await;
    assert_eq!(session(&mut b).await["idp"], "up");
    assert_eq!(
        f.fake.state.lock().unwrap().posts[0].basic,
        Some(("rustid".into(), "secret".into()))
    );

    // Disabled through admin: the next challenge and callback are 404.
    let mut disabled = provider;
    disabled["enabled"] = false.into();
    admin
        .update(
            configuration.as_ref(),
            &saved.id,
            IdentityProviderInput::from_json(disabled).unwrap(),
            1,
        )
        .await
        .unwrap()
        .unwrap();
    let mut b2 = Browser::new(&f.app);
    let login = b2.get(&authorize_for("fed.client", "")).await;
    let reply = b2
        .get(&format!(
            "/federation/up/challenge?returnUrl={}",
            encode(&return_url(&login.location()))
        ))
        .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    let reply = b2.get("/federation/up/callback?code=c&state=s").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}
