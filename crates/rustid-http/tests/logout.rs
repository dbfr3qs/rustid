//! The end session endpoint and the logout page's context.

mod browser;

use axum::http::{Method, StatusCode};
use browser::*;

/// Signs in and authorizes `web`, then `client`, so the session lists both.
async fn signed_in_with(browser: &mut Browser, client: &str) {
    sign_in(browser, "1").await;
    let r = browser.get(&authorize_uri("")).await;
    assert!(
        r.location()
            .starts_with("https://client.test/callback?code=")
    );
    let r = browser
        .get(&authorize_uri("").replace("client_id=web", &format!("client_id={client}")))
        .await;
    assert!(
        r.location()
            .starts_with("https://client.test/callback?code="),
        "{}",
        r.location()
    );
}

fn logout_id(location: &str) -> Option<String> {
    url::Url::parse(location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "logoutId")
        .map(|(_, v)| v.into_owned())
}

async fn context(browser: &Browser, logout_id: &str) -> serde_json::Value {
    let bearer = format!("Bearer {API_KEY}");
    let cookie: Vec<String> = browser
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let mut ui = Browser::new(&browser.app);
    let r = ui
        .send(
            Method::GET,
            &format!("/interaction/logout?logoutId={logout_id}"),
            &[("authorization", &bearer), ("cookie", &cookie.join("; "))],
            "",
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    serde_json::from_str(&r.body).unwrap()
}

#[tokio::test]
async fn a_signed_in_user_is_sent_to_the_logout_page_with_a_message() {
    let app = state();
    let mut browser = Browser::new(&app);
    signed_in_with(&mut browser, "logout.front").await;
    let r = browser
        .get("/connect/endsession?ui_locales=nb-NO&custom=x")
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert!(
        r.location()
            .starts_with("http://server/Account/Logout?logoutId="),
        "{}",
        r.location()
    );
    let id = logout_id(&r.location()).unwrap();
    let context = context(&browser, &id).await;
    assert_eq!(context["subjectId"], "1");
    assert_eq!(
        context["clientIds"],
        serde_json::json!(["web", "logout.front"])
    );
    assert_eq!(context["clientId"], serde_json::Value::Null);
    assert_eq!(context["showSignoutPrompt"], true);
    assert_eq!(context["uiLocales"], "nb-NO");
    assert_eq!(context["parameters"], serde_json::json!({ "custom": "x" }));
    let iframe = context["signOutIFrameUrl"].as_str().unwrap();
    assert!(
        iframe.starts_with("http://server/connect/endsession/callback?endSessionId="),
        "{iframe}"
    );
}

#[tokio::test]
async fn anonymous_requests_and_other_methods() {
    let app = state();
    let mut browser = Browser::new(&app);
    let r = browser.get("/connect/endsession").await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "http://server/Account/Logout");
    let r = browser
        .send(
            Method::POST,
            "/connect/endsession",
            &[("content-type", "application/x-www-form-urlencoded")],
            "state=x",
        )
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    let r = browser
        .send(Method::PUT, "/connect/endsession", &[], "")
        .await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED);
    // A context without a message still answers, from the session.
    let context = context(&browser, "unknown").await;
    assert_eq!(context["showSignoutPrompt"], true);
    assert_eq!(context["signOutIFrameUrl"], serde_json::Value::Null);
}

/// Records every back-channel logout token sent.
#[derive(Default)]
struct Recorder(std::sync::Mutex<Vec<(String, String)>>);

#[async_trait::async_trait]
impl rustid_core::logout::BackChannelSender for Recorder {
    async fn send(&self, uri: &str, logout_token: &str) {
        self.0
            .lock()
            .unwrap()
            .push((uri.to_owned(), logout_token.to_owned()));
    }
}

fn state_recording() -> (rustid_http::AppState, std::sync::Arc<Recorder>) {
    let recorder = std::sync::Arc::new(Recorder::default());
    let mut s = (*state().0).clone();
    s.stores.back_channel = recorder.clone();
    (rustid_http::AppState::new(s), recorder)
}

/// `POST /interaction/logout` as the UI makes it, with the browser's cookies.
async fn logout_call(browser: &Browser, body: serde_json::Value) -> Reply {
    let bearer = format!("Bearer {API_KEY}");
    let cookie: Vec<String> = browser
        .cookies
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let mut ui = Browser::new(&browser.app);
    ui.send(
        Method::POST,
        "/interaction/logout",
        &[
            ("authorization", &bearer),
            ("content-type", "application/json"),
            ("cookie", &cookie.join("; ")),
        ],
        &body.to_string(),
    )
    .await
}

fn continue_path(reply: &Reply) -> String {
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let body: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    body["continueUrl"]
        .as_str()
        .unwrap()
        .strip_prefix("http://server")
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn completing_a_logout_signs_the_browser_out_once() {
    let (app, recorder) = state_recording();
    let mut browser = Browser::new(&app);
    signed_in_with(&mut browser, "logout.back").await;
    assert!(browser.cookies.iter().any(|(k, _)| k == "idsrv"));
    let path = continue_path(
        &logout_call(
            &browser,
            serde_json::json!({ "returnUrl": "/signed-out?x=1" }),
        )
        .await,
    );
    assert!(
        path.starts_with("/connect/interaction/logout?token="),
        "{path}"
    );

    let r = browser.get(&path).await;
    assert_eq!(r.status, StatusCode::FOUND, "{}", r.body);
    assert_eq!(r.location(), "/signed-out?x=1");
    // The authentication cookie is deleted, then
    // remove session id cookie deletes the check session cookie.
    assert_eq!(
        r.set_cookies(),
        [
            "idsrv=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; samesite=none; httponly"
                .to_owned(),
            r.set_cookies()[1].clone(),
        ]
    );
    assert!(r.set_cookies()[1].starts_with("idsrv.session=.; expires="));
    assert_eq!(header(&r, "cache-control"), "no-cache,no-store");
    assert_eq!(header(&r, "pragma"), "no-cache");
    assert!(!browser.cookies.iter().any(|(k, _)| k == "idsrv"));
    let sent = recorder.0.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, "http://127.0.0.1:5192/backchannel");

    // Once only.
    let r = browser.get(&path).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn logout_continuations_are_bound_to_the_session_and_return_locally() {
    let app = state();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let r = logout_call(
        &browser,
        serde_json::json!({ "returnUrl": "https://evil.test/" }),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = logout_call(&browser, serde_json::json!({ "returnUrl": "//evil.test/" })).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);

    // Another browser (another session, or none) can't use it.
    let path = continue_path(&logout_call(&browser, serde_json::json!({ "returnUrl": "/" })).await);
    let mut other = Browser::new(&app);
    assert_eq!(other.get(&path).await.status, StatusCode::BAD_REQUEST);
    let path = continue_path(&logout_call(&browser, serde_json::json!({ "returnUrl": "/" })).await);
    let mut elsewhere = Browser::new(&app);
    sign_in(&mut elsewhere, "1").await;
    assert_eq!(elsewhere.get(&path).await.status, StatusCode::BAD_REQUEST);
    // A refused visit uses the continuation up, as a login's does.
    assert_eq!(browser.get(&path).await.status, StatusCode::BAD_REQUEST);
    let path = continue_path(&logout_call(&browser, serde_json::json!({ "returnUrl": "/" })).await);
    assert_eq!(browser.get(&path).await.status, StatusCode::FOUND);

    // An anonymous browser can complete an anonymous logout.
    let mut anonymous = Browser::new(&app);
    let path =
        continue_path(&logout_call(&anonymous, serde_json::json!({ "returnUrl": "/" })).await);
    assert_eq!(anonymous.get(&path).await.status, StatusCode::FOUND);
}

fn header<'a>(reply: &'a Reply, name: &str) -> &'a str {
    reply
        .headers
        .get(name)
        .map(|v| v.to_str().unwrap())
        .unwrap_or_default()
}

#[tokio::test]
async fn the_end_session_callback_renders_the_front_channel_iframes() {
    let app = state();
    let mut browser = Browser::new(&app);
    signed_in_with(&mut browser, "logout.front").await;
    let session_id = browser
        .cookies
        .iter()
        .find(|(k, _)| k == "idsrv.session")
        .unwrap()
        .1
        .clone();
    let r = browser.get("/connect/endsession").await;
    let context = context(&browser, &logout_id(&r.location()).unwrap()).await;
    let iframe = context["signOutIFrameUrl"]
        .as_str()
        .unwrap()
        .strip_prefix("http://server")
        .unwrap()
        .to_owned();

    // Any browser can load it: the id is the credential.
    let mut other = Browser::new(&app);
    let r = other.get(&iframe).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(header(&r, "content-type"), "text/html; charset=UTF-8");
    assert_eq!(header(&r, "cache-control"), "no-store, no-cache, max-age=0");
    assert!(r.body.starts_with(
        "<!DOCTYPE html><html><style>iframe{{display:none;width:0;height:0;}}</style><body>"
    ));
    let expected = format!(
        "<iframe loading='eager' allow='' src='https://client.test/front?sid={session_id}&amp;iss=https%3A%2F%2Fidsrv.test'></iframe>\n"
    );
    assert!(r.body.contains(&expected), "{}", r.body);
    assert_eq!(r.body.matches("<iframe").count(), 1, "web has no URI");
    assert!(r.body.ends_with("</script>"));
    let csp = header(&r, "content-security-policy");
    assert!(
        csp.starts_with("default-src 'none'; style-src 'sha256-"),
        "{csp}"
    );
    assert!(csp.ends_with("; frame-src https://client.test"), "{csp}");

    assert_eq!(
        other
            .get("/connect/endsession/callback?endSessionId=nope")
            .await
            .status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        other.get("/connect/endsession/callback").await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        other.send(Method::POST, &iframe, &[], "").await.status,
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn the_check_session_page_names_the_cookie_and_hashes_its_script() {
    let app = state();
    let mut browser = Browser::new(&app);
    let r = browser.get("/connect/checksession").await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(header(&r, "content-type"), "text/html; charset=UTF-8");
    assert!(
        r.body
            .contains("<script id='cookie-name' type='application/json'>idsrv.session</script>"),
        "{}",
        r.body
    );
    let script = r
        .body
        .split("<script>")
        .nth(1)
        .and_then(|s| s.split("</script>").next())
        .unwrap();
    use base64::Engine;
    let hash = base64::engine::general_purpose::STANDARD
        .encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, script.as_bytes()).as_ref());
    assert_eq!(
        header(&r, "content-security-policy"),
        format!("default-src 'none'; script-src 'sha256-{hash}'")
    );
    assert_eq!(
        browser
            .send(Method::POST, "/connect/checksession", &[], "")
            .await
            .status,
        StatusCode::METHOD_NOT_ALLOWED
    );

    let mut options = rustid_core::options::ProtocolOptions::default();
    options.endpoints.enable_check_session_endpoint = false;
    let mut disabled = Browser::new(&state_with(options));
    assert_eq!(
        disabled.get("/connect/checksession").await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn ui_locales_set_the_culture_cookie_even_when_the_hint_is_refused() {
    let mut s = (*state().0).clone();
    s.interaction.supported_ui_cultures = vec!["nb-NO".to_owned()];
    let app = rustid_http::AppState::new(s);
    let mut browser = Browser::new(&app);
    let r = browser
        .get("/connect/endsession?id_token_hint=not-a-token&ui_locales=nb-NO")
        .await;
    assert_eq!(r.status, StatusCode::SEE_OTHER);
    assert_eq!(r.location(), "http://server/Account/Logout");
    assert!(
        r.set_cookies()
            .iter()
            .any(|c| c.starts_with(".AspNetCore.Culture=c%3Dnb-NO")),
        "{:?}",
        r.set_cookies()
    );
}

/// Runs `script` under node with `setup` (fakes for the browser APIs it
/// uses) and returns what it printed; `None` when node isn't installed.
fn run_node(setup: &str, script: &str, after: &str) -> Option<String> {
    let program = format!("{setup}\n{script}\n{after}");
    let path = std::env::temp_dir().join(format!(
        "rustid-script-{}-{}.js",
        std::process::id(),
        rand_suffix()
    ));
    std::fs::write(&path, program).unwrap();
    let output = std::process::Command::new("node").arg(&path).output();
    let _ = std::fs::remove_file(&path);
    let output = match output {
        Ok(output) => output,
        Err(_) => {
            eprintln!("node not found: skipping the script check");
            return None;
        }
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8(output.stdout).unwrap())
}

fn rand_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

#[tokio::test]
async fn the_check_session_script_recomputes_the_authorize_session_state() {
    let app = state();
    let mut browser = Browser::new(&app);
    sign_in(&mut browser, "1").await;
    let r = browser.get(&authorize_uri("")).await;
    let session_state = url::Url::parse(&r.location())
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "session_state")
        .unwrap()
        .1
        .into_owned();
    let session_id = browser
        .cookies
        .iter()
        .find(|(k, _)| k == "idsrv.session")
        .unwrap()
        .1
        .clone();
    let page = browser.get("/connect/checksession").await.body;
    let script = page
        .split("<script>")
        .nth(1)
        .and_then(|s| s.split("</script>").next())
        .unwrap();
    let setup = format!(
        r#"
const listeners = [];
globalThis.window = globalThis;
globalThis.addEventListener = (type, f) => listeners.push(f);
globalThis.document = {{
  getElementById: () => ({{ textContent: " idsrv.session " }}),
  cookie: "other=1; idsrv.session={session_id}",
}};
"#
    );
    let after = format!(
        r#"
const replies = [];
const send = (data, origin) => listeners.forEach(f =>
  f({{ data, origin, source: {{ postMessage: (m, o) => replies.push([data.slice(0, 3), origin, m, o]) }} }}));
send("web {session_state}", "https://client.test");
send("web {session_state}", "https://other.test");
send("spa {session_state}", "https://client.test");
send("garbage", "https://client.test");
// Replies come as the digests finish: wait for each batch.
const until = (count, then) => {{
  const check = () => (replies.length >= count ? then() : setTimeout(check, 5));
  check();
}};
until(4, () => {{
  replies.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b)));
  document.cookie = "other=1";
  send("web {session_state}", "https://client.test");
  until(5, () => console.log(JSON.stringify(replies)));
}});
"#
    );
    let Some(out) = run_node(&setup, script, &after) else {
        return;
    };
    let replies: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(
        replies,
        serde_json::json!([
            ["gar", "https://client.test", "error", "https://client.test"],
            [
                "spa",
                "https://client.test",
                "changed",
                "https://client.test"
            ],
            [
                "web",
                "https://client.test",
                "unchanged",
                "https://client.test"
            ],
            ["web", "https://other.test", "changed", "https://other.test"],
            [
                "web",
                "https://client.test",
                "changed",
                "https://client.test"
            ],
        ])
    );
}

#[test]
fn the_callback_script_completes_at_once_without_iframes() {
    let setup = r#"
const events = [];
globalThis.window = globalThis;
globalThis.parent = { postMessage: (m, o) => events.push(["posted", m, o]) };
globalThis.document = {
  getElementsByTagName: () => [],
  documentElement: { setAttribute: (k, v) => events.push(["attribute", k, v]) },
};
"#;
    let script = include_str!("../src/scripts/end-session-callback.js");
    let Some(out) = run_node(setup, script, "console.log(JSON.stringify(events));") else {
        return;
    };
    let events: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(
        events,
        serde_json::json!([
            ["attribute", "data-signout", "complete"],
            ["posted", "rustid:signout-complete", "*"],
        ])
    );
}
