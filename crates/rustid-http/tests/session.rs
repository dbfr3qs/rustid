//! Signing in through the interaction API, the session cookies, and the
//! authorize endpoint's answers for a signed-in user.

use axum::http::{Method, StatusCode};
use rustid_core::clients::Clients;
use rustid_core::grants::GrantFilter;
use rustid_core::resources::Resources;
use rustid_http::{AppState, InteractionState, ProtocolState};

mod browser;

use browser::*;

#[tokio::test]
async fn signing_in_writes_both_session_cookies() {
    let app = state();
    let mut browser = Browser::new(&app);
    let login = browser.get(&authorize_uri("")).await;
    let return_url = return_url(&login.location());
    let api = login_call(&mut browser, &return_url, "1").await;
    let continue_url: serde_json::Value = serde_json::from_str(&api.body).unwrap();
    let continue_url = continue_url["continueUrl"].as_str().unwrap();
    assert!(continue_url.starts_with("http://server/connect/interaction/continue?token="));
    let signed_in = browser
        .get(continue_url.strip_prefix("http://server").unwrap())
        .await;
    let cookies = signed_in.set_cookies();
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    assert!(
        cookies[0].starts_with("idsrv.session=") && cookies[0].ends_with("; path=/; samesite=none")
    );
    assert_eq!(signed_in.cookie("idsrv.session").unwrap().len(), 32);
    assert!(
        cookies[1].starts_with("idsrv=")
            && cookies[1].ends_with("; path=/; samesite=none; httponly")
    );
}

#[tokio::test]
async fn over_https_urls_use_https_and_session_cookies_are_secure() {
    let app = state_with(Default::default());
    let mut browser = Browser::new(&app);
    browser.https = true;
    let discovery = browser.get("/.well-known/openid-configuration").await;
    let document: serde_json::Value = serde_json::from_str(&discovery.body).unwrap();
    // The fixture state pins issuer_uri; every other URL follows the request.
    assert_eq!(
        document["authorization_endpoint"],
        "https://server/connect/authorize"
    );
    let login = browser.get(&authorize_uri("")).await;
    assert!(
        login
            .location()
            .starts_with("https://server/Account/Login?"),
        "{}",
        login.location()
    );
    assert!(
        login
            .set_cookies()
            .iter()
            .any(|c| c.starts_with("idsrv.interaction=")
                && c.ends_with("; path=/; secure; samesite=none; httponly")),
        "{:?}",
        login.set_cookies()
    );
    let return_url = return_url(&login.location());
    let api = login_call(&mut browser, &return_url, "1").await;
    let continue_url: serde_json::Value = serde_json::from_str(&api.body).unwrap();
    let continue_url = continue_url["continueUrl"].as_str().unwrap();
    assert!(continue_url.starts_with("https://server/connect/interaction/continue?token="));
    let signed_in = browser
        .get(continue_url.strip_prefix("https://server").unwrap())
        .await;
    let cookies = signed_in.set_cookies();
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    assert!(cookies[0].ends_with("; path=/; secure; samesite=none"));
    assert!(cookies[1].ends_with("; path=/; secure; samesite=none; httponly"));
    // The authorize response rewrites idsrv with the client added.
    let r = browser.get(&return_url).await;
    assert!(
        r.set_cookies()
            .iter()
            .any(|c| c.starts_with("idsrv=") && c.contains("; secure;")),
        "{:?}",
        r.set_cookies()
    );
}

#[tokio::test]
async fn a_signed_in_user_gets_a_code_without_the_error_fragment_marker() {
    let app = state();
    let mut browser = Browser::new(&app);
    let callback = sign_in(&mut browser, "1").await;
    let r = browser.get(&callback).await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let location = r.location();
    assert!(
        location.starts_with("https://client.test/callback?code=")
            && location.contains("&state=s1&session_state=")
            && location.ends_with("&iss=https%3A%2F%2Fidsrv.test"),
        "{location}"
    );
    assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    assert!(
        r.cookie("idsrv").is_some(),
        "the client joins the session's client list"
    );

    let again = browser.get(&authorize_uri("&state=s2")).await;
    assert!(
        again
            .location()
            .starts_with("https://client.test/callback?code=")
    );
    assert!(
        again.cookie("idsrv").is_none(),
        "the client is already listed"
    );

    let codes = app
        .0
        .stores
        .grants
        .get_all(&GrantFilter {
            subject_id: Some("1".into()),
            grant_type: Some("authorization_code".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(codes.len(), 2);
    assert_eq!(codes[0].client_id, "web");
}

#[tokio::test]
async fn a_continuation_works_once_and_only_in_the_browser_that_started_it() {
    let app = state();
    let mut browser = Browser::new(&app);
    let login = browser.get(&authorize_uri("")).await;
    let return_url = return_url(&login.location());
    let api = login_call(&mut browser, &return_url, "1").await;
    let continue_url: serde_json::Value = serde_json::from_str(&api.body).unwrap();
    let path = continue_url["continueUrl"]
        .as_str()
        .unwrap()
        .strip_prefix("http://server")
        .unwrap()
        .to_owned();

    let mut other = Browser::new(&app);
    let stolen = other.get(&path).await;
    assert_eq!(stolen.status, StatusCode::BAD_REQUEST);
    assert!(stolen.cookie("idsrv").is_none());
    // The attempt consumed it: even the right browser can't use it now.
    assert_eq!(browser.get(&path).await.status, StatusCode::BAD_REQUEST);

    let api = login_call(&mut browser, &return_url, "1").await;
    let continue_url: serde_json::Value = serde_json::from_str(&api.body).unwrap();
    let path = continue_url["continueUrl"]
        .as_str()
        .unwrap()
        .strip_prefix("http://server")
        .unwrap()
        .to_owned();
    assert_eq!(browser.get(&path).await.status, StatusCode::FOUND);
    assert_eq!(
        browser.get(&path).await.status,
        StatusCode::BAD_REQUEST,
        "one time only"
    );
    assert_eq!(
        browser
            .get("/connect/interaction/continue?token=nope")
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn the_login_api_checks_its_key_body_and_return_url() {
    let app = state();
    let mut ui = Browser::new(&app);
    let bearer = format!("Bearer {API_KEY}");
    let json = ("content-type", "application/json");
    let r = ui
        .send(
            Method::POST,
            "/interaction/login",
            &[json],
            r#"{"returnUrl":"/connect/authorize/callback","subjectId":"1"}"#,
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    let r = ui
        .send(
            Method::POST,
            "/interaction/login",
            &[("authorization", &bearer), ("content-type", "text/plain")],
            "{}",
        )
        .await;
    assert_eq!(r.status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    for body in [
        r#"{"returnUrl":"https://evil.test/connect/authorize/callback","subjectId":"1"}"#,
        r#"{"returnUrl":"/connect/token","subjectId":"1"}"#,
        r#"{"returnUrl":"/connect/authorize/callback","subjectId":" "}"#,
        r#"{"returnUrl":"/connect/authorize/callback"}"#,
        r#"{"returnUrl":"/connect/authorize/callback","subjectId":"1","unknown":1}"#,
    ] {
        let r = ui
            .send(
                Method::POST,
                "/interaction/login",
                &[("authorization", &bearer), json],
                body,
            )
            .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{body}");
    }
}

#[tokio::test]
async fn the_login_context_describes_the_request() {
    let app = state();
    let mut browser = Browser::new(&app);
    let login = browser
        .get(&authorize_uri(
            "&login_hint=alice&acr_values=idp:google%20tenant:t1%20urn:x&prompt=login",
        ))
        .await;
    let return_url = return_url(&login.location());
    let bearer = format!("Bearer {API_KEY}");
    let uri = format!(
        "/interaction/login?returnUrl={}",
        rustid_core::params::url_encode(&return_url)
    );
    let r = browser
        .send(Method::GET, &uri, &[("authorization", &bearer)], "")
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let context: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(context["clientId"], "web");
    assert_eq!(context["loginHint"], "alice");
    assert_eq!(context["idP"], "google");
    assert_eq!(context["tenant"], "t1");
    assert_eq!(context["acrValues"], serde_json::json!(["urn:x"]));
    assert_eq!(context["promptModes"], serde_json::json!(["login"]));
    assert_eq!(context["scopes"], serde_json::json!(["openid", "api1"]));
    assert_eq!(context["parameters"]["suppressed_prompt"], "login");
    let r = browser
        .send(
            Method::GET,
            "/interaction/login?returnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Dnope",
            &[("authorization", &bearer)],
            "",
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_check_session_cookie_follows_the_session() {
    let app = state();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let sid = browser
        .cookies
        .iter()
        .find(|(k, _)| k == "idsrv.session")
        .unwrap()
        .1
        .clone();
    let r = browser.get("/.well-known/openid-configuration").await;
    assert!(r.set_cookies().is_empty(), "nothing to do while they agree");
    browser.drop_cookie("idsrv.session");
    let r = browser.get("/.well-known/openid-configuration").await;
    assert_eq!(
        r.cookie("idsrv.session"),
        Some(sid),
        "reissued with the same id"
    );
    browser.drop_cookie("idsrv");
    let r = browser.get("/health").await;
    let cookies = r.set_cookies();
    assert_eq!(cookies.len(), 1);
    assert!(
        cookies[0].starts_with("idsrv.session=.; expires="),
        "{}",
        cookies[0]
    );
}

#[tokio::test]
async fn signing_in_again_as_the_same_user_keeps_the_session_id() {
    let app = state();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let sid = |b: &Browser| {
        b.cookies
            .iter()
            .find(|(k, _)| k == "idsrv.session")
            .unwrap()
            .1
            .clone()
    };
    let first = sid(&browser);
    sign_in(&mut browser, "1").await;
    assert_eq!(sid(&browser), first);
    sign_in(&mut browser, "2").await;
    assert_ne!(sid(&browser), first);
}

#[tokio::test]
async fn consent_clients_go_to_the_consent_page_and_custom_prompts_fail() {
    let app = state();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let r = browser
        .get(&authorize_uri("").replace("client_id=web", "client_id=web-consent"))
        .await;
    assert!(
        r.location()
            .starts_with("http://server/consent?returnUrl=%2Fconnect%2Fauthorize%2Fcallback%3F"),
        "{}",
        r.location()
    );
    let r = browser
        .get(&authorize_uri("&prompt=none").replace("client_id=web", "client_id=web-consent"))
        .await;
    assert!(
        r.location()
            .starts_with("https://client.test/callback?error=consent_required"),
        "{}",
        r.location()
    );
}

#[tokio::test]
async fn codes_redeem_at_the_token_endpoint_with_the_id_token_first() {
    let app = state_with(rustid_core::options::ProtocolOptions {
        emit_state_hash: true,
        ..Default::default()
    });
    let mut browser = Browser::new(&app);
    let callback = sign_in(&mut browser, "1").await;
    let r = browser.get(&callback).await;
    let location = url::Url::parse(&r.location()).unwrap();
    let code = location
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let form = format!(
        "grant_type=authorization_code&client_id=web&code={code}&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );
    let r = browser
        .send(
            Method::POST,
            "/connect/token",
            &[("content-type", "application/x-www-form-urlencoded")],
            &form,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.starts_with(r#"{"id_token":""#), "{}", r.body);
    let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let keys: Vec<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        [
            "id_token",
            "access_token",
            "expires_in",
            "token_type",
            "scope"
        ]
    );
    let id_token = rustid_core::jwt::Jws::decode(body["id_token"].as_str().unwrap()).unwrap();
    assert_eq!(
        id_token.payload["s_hash"],
        rustid_core::tokens::hash_claim_value("s1", "RS256").as_str()
    );
}

#[tokio::test]
async fn userinfo_answers_with_claims_or_bearer_errors() {
    let app = state();
    let mut browser = Browser::new(&app);
    let callback = sign_in(&mut browser, "1").await;
    let r = browser.get(&callback).await;
    let location = url::Url::parse(&r.location()).unwrap();
    let code = location
        .query_pairs()
        .find(|(k, _)| k == "code")
        .unwrap()
        .1
        .into_owned();
    let form = format!(
        "grant_type=authorization_code&client_id=web&code={code}&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    );
    let form_type = ("content-type", "application/x-www-form-urlencoded");
    let r = browser
        .send(Method::POST, "/connect/token", &[form_type], &form)
        .await;
    let body: serde_json::Value = serde_json::from_str(&r.body).unwrap();
    let token = body["access_token"].as_str().unwrap().to_owned();

    let bearer = format!("Bearer {token}");
    let r = browser
        .send(
            Method::GET,
            "/connect/userinfo",
            &[("authorization", &bearer)],
            "",
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.headers["content-type"], "application/json; charset=UTF-8");
    assert_eq!(r.headers["cache-control"], "no-store, no-cache, max-age=0");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&r.body).unwrap(),
        serde_json::json!({ "sub": "1" })
    );
    let r = browser
        .send(
            Method::POST,
            "/connect/userinfo",
            &[form_type],
            &format!("access_token={token}"),
        )
        .await;
    assert_eq!(r.status, StatusCode::OK);
    // The bearer token usage validator takes whatever follows `Bearer`, trimmed.
    for header in [
        format!("Bearer\t{token}"),
        format!("Bearer  {token}"),
        format!("Bearer{token}"),
    ] {
        let r = browser
            .send(
                Method::GET,
                "/connect/userinfo",
                &[("authorization", &header)],
                "",
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{header:?}: {}", r.body);
    }

    let r = browser
        .send(
            Method::GET,
            "/connect/userinfo",
            &[("authorization", "bearer x")],
            "",
        )
        .await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        r.headers["www-authenticate"],
        "Bearer realm=\"rustid\",error=\"invalid_token\""
    );
    assert_eq!(r.headers["pragma"], "no-cache");
    let r = browser
        .send(Method::DELETE, "/connect/userinfo", &[], "")
        .await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[derive(Default)]
struct Recording(std::sync::Mutex<Vec<rustid_core::events::Event>>);

impl rustid_core::events::EventSink for Recording {
    fn persist(&self, event: &rustid_core::events::Event) {
        self.0.lock().unwrap().push(event.clone());
    }
}

#[tokio::test]
async fn a_state_hash_without_a_signing_key_is_an_unhandled_exception_with_the_plain_message() {
    // `web` allows only ES256 identity tokens and there is only an RS256
    // key, so hashing `state` for the code fails.
    let mut clients = Clients::load(&fixture("clients.json")).unwrap();
    for client in &mut clients.clients {
        if client.client_id == "web" {
            client.allowed_identity_token_signing_algorithms = vec!["ES256".into()];
        }
    }
    let sink = std::sync::Arc::new(Recording::default());
    let app = AppState::new(ProtocolState {
        options: rustid_core::options::ProtocolOptions {
            issuer_uri: Some("https://idsrv.test".into()),
            emit_state_hash: true,
            ..Default::default()
        },
        keys: signing_keys(),
        features: Default::default(),
        stores: rustid_store_memory::stores(
            clients,
            Resources::load(&fixture("resources.json")).unwrap(),
        ),
        events: rustid_core::events::EventService::new(
            rustid_core::options::EventsOptions {
                raise_error_events: true,
                ..Default::default()
            },
            sink.clone(),
        ),
        path_base: None,
        protected_resource: None,
        dcr: None,
        saml: Default::default(),
        interaction: InteractionState {
            api_keys: vec![API_KEY.to_owned()],
            ..Default::default()
        },
    });
    let mut browser = Browser::new(&app);
    let callback = sign_in(&mut browser, "1").await;
    let r = browser.get(&callback).await;
    assert_eq!(r.status, StatusCode::INTERNAL_SERVER_ERROR, "{}", r.body);
    let events = sink.0.lock().unwrap().clone();
    let unhandled: Vec<_> = events
        .iter()
        .filter(|e| e.name == "Unhandled Exception")
        .collect();
    assert_eq!(unhandled.len(), 1, "{events:?}");
    assert_eq!(
        unhandled[0].message.as_deref(),
        Some("No signing credential is configured.")
    );
}
