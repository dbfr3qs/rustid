//! SAML configuration: `[saml]` enables the IdP's stores and options, and
//! loads service providers from a file (imported into Postgres there).

use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn config(dir: &Path, saml: serde_json::Value, store: serde_json::Value) -> ServerConfig {
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "saml": saml,
        "store": store,
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    ServerConfig::load(Some(&path)).unwrap()
}

#[tokio::test]
async fn saml_is_off_by_default_and_reads_its_options() {
    let dir = tempfile::tempdir().unwrap();
    let app = rustid_server::build(&config(
        dir.path(),
        serde_json::json!({}),
        serde_json::json!({}),
    ))
    .await
    .unwrap();
    assert!(app.saml().is_none());

    let on = config(
        dir.path(),
        serde_json::json!({
            "enabled": true,
            "service_providers_file": fixture("saml-service-providers.json"),
            "entity_id": "urn:rustid:idp",
            "default_signing_behavior": "SignBoth",
            "endpoints": { "single_sign_on_service_path": "/custom/sso" },
        }),
        serde_json::json!({}),
    );
    let app = rustid_server::build(&on).await.unwrap();
    let saml = app.saml().unwrap();
    assert_eq!(saml.options.entity_id.as_deref(), Some("urn:rustid:idp"));
    assert_eq!(
        saml.options.endpoints.single_sign_on_service_path,
        "/custom/sso"
    );
    assert_eq!(
        saml.options.endpoints.single_logout_service_path,
        "/Saml2/SLO"
    );
    let sp = saml
        .stores
        .service_providers
        .find_by_entity_id("https://sp.example")
        .await
        .unwrap();
    assert!(sp.is_some());
    assert!(
        saml.stores
            .service_providers
            .find_by_entity_id("https://disabled.example")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn bad_saml_configuration_refuses_to_start() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rustid.json");
    std::fs::write(
        &path,
        serde_json::json!({ "saml": { "enabled": true, "no_such_option": 1 } }).to_string(),
    )
    .unwrap();
    let error = ServerConfig::load(Some(&path)).unwrap_err();
    assert!(format!("{error:#}").contains("no_such_option"), "{error:#}");

    let duplicate = dir.path().join("sps.json");
    std::fs::write(
        &duplicate,
        r#"[{"entityId":"a","assertionConsumerServiceUrls":[],"allowedScopes":[]},{"entityId":"a"}]"#,
    )
    .unwrap();
    let cfg = config(
        dir.path(),
        serde_json::json!({ "enabled": true, "service_providers_file": duplicate }),
        serde_json::json!({}),
    );
    let error = rustid_server::build(&cfg).await.err().unwrap();
    assert!(
        format!("{error:#}").contains("duplicate entity IDs"),
        "{error:#}"
    );
}

#[tokio::test]
async fn postgres_serves_the_imported_service_providers() {
    let Some(db) = rustid_testkit_scratch().await else {
        eprintln!("skipped: TEST_POSTGRES_URL is not set");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(
        dir.path(),
        serde_json::json!({ "enabled": true, "service_providers_file": fixture("saml-service-providers.json") }),
        serde_json::json!({ "kind": "postgres", "postgres": { "url": db } }),
    );
    let app = rustid_server::build(&cfg).await.unwrap();
    let saml = app.saml().unwrap();
    assert!(
        saml.stores
            .service_providers
            .find_by_entity_id("https://sp.example")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        saml.stores.service_providers.get_all().await.unwrap().len(),
        rustid_saml::model::load_service_providers(&fixture("saml-service-providers.json"))
            .unwrap()
            .len()
            - 1,
        "every fixture provider but the invalid noacs.example"
    );
}

/// A fresh database on the TEST_POSTGRES_URL server.
async fn rustid_testkit_scratch() -> Option<String> {
    let base = std::env::var("TEST_POSTGRES_URL").ok()?;
    let name = format!("saml_{}", std::process::id());
    let admin = sqlx::PgPool::connect(&base).await.ok()?;
    let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
        "DROP DATABASE IF EXISTS {name}"
    )))
    .execute(&admin)
    .await;
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
        .execute(&admin)
        .await
        .ok()?;
    let mut url = url::Url::parse(&base).ok()?;
    url.set_path(&name);
    Some(url.to_string())
}

/// A server with a certificate signing key and `[saml]` from `saml`,
/// listening on a random port.
async fn start_saml(
    dir: &Path,
    saml: serde_json::Value,
    signing_cert: bool,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    let key = if signing_cert {
        serde_json::json!({ "kid": "k1", "alg": "RS256",
            "key_file": fixture("validation-cert-key.pem"), "cert_file": fixture("validation-cert.pem") })
    } else {
        serde_json::json!({ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") })
    };
    let config = serde_json::json!({
        "signing_keys": [key],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "saml": saml,
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let app = rustid_server::build(&ServerConfig::load(Some(&path)).unwrap())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    (base, stop)
}

#[tokio::test]
async fn metadata_is_served_at_saml2() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start_saml(dir.path(), serde_json::json!({ "enabled": true }), true).await;
    let client = reqwest::Client::new();
    let response = client.get(format!("{base}/saml2")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "application/samlmetadata+xml"
    );
    let body = response.text().await.unwrap();
    assert!(body.starts_with("<md:EntityDescriptor ID=\""), "{body}");
    assert!(
        body.contains(&format!(r#"entityID="{base}/Saml2""#)),
        "the issuer from the request: {body}"
    );
    assert!(body.contains(&format!(r#"Location="{base}/Saml2/SSO""#)));
    let cert = std::fs::read_to_string(fixture("validation-cert.pem")).unwrap();
    let cert: String = cert.lines().filter(|l| !l.starts_with("-----")).collect();
    assert!(body.contains(&format!("<ds:X509Certificate>{cert}</ds:X509Certificate>")));

    let browser = client
        .get(format!("{base}/SAML2"))
        .header("accept", "text/html,application/xhtml+xml")
        .send()
        .await
        .unwrap();
    assert_eq!(browser.status(), 200, "matched case-insensitively");
    assert_eq!(browser.headers()["content-type"], "text/xml");

    for method in [reqwest::Method::POST, reqwest::Method::HEAD] {
        let response = client
            .request(method.clone(), format!("{base}/Saml2"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 405, "{method}");
    }
}

#[tokio::test]
async fn metadata_follows_the_entity_id_path() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start_saml(
        dir.path(),
        serde_json::json!({ "enabled": true, "entity_id": "https://idp.example.com/custom/saml" }),
        true,
    )
    .await;
    let get = |path: &str| reqwest::get(format!("{base}{path}"));
    let custom = get("/custom/saml").await.unwrap();
    assert_eq!(custom.status(), 200);
    assert!(
        custom
            .text()
            .await
            .unwrap()
            .contains(r#"entityID="https://idp.example.com/custom/saml""#)
    );
    assert_eq!(get("/Saml2").await.unwrap().status(), 404);

    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start_saml(
        dir.path(),
        serde_json::json!({ "enabled": true, "entity_id": "urn:my:custom:idp" }),
        true,
    )
    .await;
    assert_eq!(
        reqwest::get(format!("{base}/Saml2"))
            .await
            .unwrap()
            .status(),
        200
    );
}

#[tokio::test]
async fn metadata_needs_saml_and_signing_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start_saml(dir.path(), serde_json::json!({}), true).await;
    assert_eq!(
        reqwest::get(format!("{base}/Saml2"))
            .await
            .unwrap()
            .status(),
        404
    );

    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start_saml(dir.path(), serde_json::json!({ "enabled": true }), false).await;
    assert_eq!(
        reqwest::get(format!("{base}/Saml2"))
            .await
            .unwrap()
            .status(),
        500,
        "a static RSA key without a certificate is a 500"
    );
}

fn sp_credential() -> rustid_saml::xml::dsig::Credential {
    rustid_saml::xml::dsig::Credential::from_pem(
        &std::fs::read_to_string(fixture("saml/sp/sp-signing.cert.pem")).unwrap(),
        &std::fs::read_to_string(fixture("saml/sp/sp-signing.key.pem")).unwrap(),
    )
    .unwrap()
}

fn authn_request(issuer: &str, extra: &str) -> String {
    format!(
        r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" IssueInstant="{}"{extra}><saml:Issuer>{issuer}</saml:Issuer></samlp:AuthnRequest>"#,
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    )
}

fn no_redirects() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn saml_sso_server(
    dir: &Path,
    saml: serde_json::Value,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    let mut saml = saml;
    saml["enabled"] = true.into();
    saml["service_providers_file"] = fixture("saml-service-providers.json")
        .display()
        .to_string()
        .into();
    start_saml(dir, saml, true).await
}

#[tokio::test]
async fn sso_requests_go_to_login_with_their_state_stored() {
    use rustid_saml::bindings::{MessageName, redirect};
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = saml_sso_server(dir.path(), serde_json::json!({})).await;
    let client = no_redirects();
    // Signed, as sp.example requires, over the redirect binding.
    let xml = authn_request(
        "https://sp.example",
        &format!(r#" Destination="{base}/Saml2/SSO""#),
    );
    let query = redirect::encode(
        MessageName::SamlRequest,
        &xml,
        Some("state-1"),
        Some(&sp_credential()),
    )
    .unwrap();
    let response = client
        .get(format!("{base}/Saml2/SSO{query}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    let prefix =
        format!("{base}/Account/Login?ReturnUrl=%2FSaml2%2FSSO%2FCallback%3FsamlStateId%3D");
    assert!(location.starts_with(&prefix), "{location}");
    // Unsigned, over POST, for an SP that allows it.
    let xml = authn_request("https://idp-initiated.example", "");
    use base64::Engine;
    let response = client
        .post(format!("{base}/saml2/sso"))
        .form(&[(
            "SAMLRequest",
            base64::engine::general_purpose::STANDARD.encode(&xml),
        )])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303, "matched case-insensitively");
    assert!(
        response.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with(&prefix)
    );
}

#[tokio::test]
async fn sso_errors_go_to_the_error_page() {
    use rustid_saml::bindings::{MessageName, redirect};
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = saml_sso_server(dir.path(), serde_json::json!({})).await;
    let client = no_redirects();
    // Response.Redirect: a 302 to the relative error page URL.
    let error_prefix = "/home/error?errorId=";
    let unknown = redirect::encode(
        MessageName::SamlRequest,
        &authn_request("https://nobody.example", ""),
        None,
        None,
    )
    .unwrap();
    for url in [
        format!("{base}/Saml2/SSO"),
        format!("{base}/Saml2/SSO?SAMLRequest=%%%"),
        format!("{base}/Saml2/SSO{unknown}"),
        // sp.example requires a signature.
        format!(
            "{base}/Saml2/SSO{}",
            redirect::encode(
                MessageName::SamlRequest,
                &authn_request("https://sp.example", ""),
                None,
                None
            )
            .unwrap()
        ),
    ] {
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 302, "{url}");
        let location = response.headers()["location"].to_str().unwrap();
        assert!(location.starts_with(error_prefix), "{url}: {location}");
    }
    // Not DEFLATE: a failure that isn't handled.
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD.encode("plain");
    let response = client
        .get(format!(
            "{base}/Saml2/SSO?SAMLRequest={}",
            redirect::escape(&raw)
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 500);
}

/// A server with SAML, the fixture SPs and the scripted reference UI, and
/// a browser (cookies, no automatic redirects).
async fn saml_browser_server(
    dir: &Path,
) -> (String, reqwest::Client, tokio::sync::oneshot::Sender<()>) {
    saml_browser_server_with(dir, false).await
}

async fn saml_browser_server_with(
    dir: &Path,
    interactive: bool,
) -> (String, reqwest::Client, tokio::sync::oneshot::Sender<()>) {
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256",
            "key_file": fixture("validation-cert-key.pem"), "cert_file": fixture("validation-cert.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "reference_ui": { "enabled": true, "interactive": interactive, "users_file": fixture("users.json"), "default_user": "alice" },
        "saml": { "enabled": true, "service_providers_file": fixture("saml-service-providers.json") },
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let app = rustid_server::build(&ServerConfig::load(Some(&path)).unwrap())
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    let browser = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    (base, browser, stop)
}

/// Follows redirects on the server until a page answers.
async fn follow(browser: &reqwest::Client, base: &str, mut url: String) -> reqwest::Response {
    for _ in 0..10 {
        if url.starts_with('/') {
            url = format!("{base}{url}");
        }
        let response = browser.get(&url).send().await.unwrap();
        if !response.status().is_redirection() {
            return response;
        }
        url = response.headers()["location"].to_str().unwrap().to_owned();
    }
    panic!("too many redirects");
}

/// The SAMLResponse of an auto-post page, decoded.
fn posted_response(html: &str) -> String {
    use base64::Engine;
    let start = html.find("name=\"SAMLResponse\"\nvalue=\"").unwrap()
        + "name=\"SAMLResponse\"\nvalue=\"".len();
    let end = start + html[start..].find('"').unwrap();
    String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(&html[start..end])
            .unwrap(),
    )
    .unwrap()
}

fn certificate_der() -> Vec<u8> {
    pem::parse(std::fs::read_to_string(fixture("validation-cert.pem")).unwrap())
        .unwrap()
        .into_contents()
}

#[tokio::test]
async fn sso_signs_in_then_responds_with_a_signed_assertion() {
    use rustid_saml::bindings::{MessageName, redirect};
    use rustid_saml::xml::dom::{Limits, parse};
    use rustid_saml::xml::dsig::{DEFAULT_ALLOWED, verify};
    let dir = tempfile::tempdir().unwrap();
    let (base, browser, _stop) = saml_browser_server(dir.path()).await;
    let query = redirect::encode(
        MessageName::SamlRequest,
        &authn_request("https://unsigned.example", ""),
        Some("state-1"),
        None,
    )
    .unwrap();
    let page = follow(&browser, &base, format!("/Saml2/SSO{query}")).await;
    assert_eq!(page.status(), 200);
    assert_eq!(page.headers()["content-type"], "text/html");
    assert_eq!(
        page.headers()["content-security-policy"],
        "script-src 'sha256-1cDf9gWlS6Mjg+iEJCbdzTerOHORw4iNiJr4endY8Ng='"
    );
    let html = page.text().await.unwrap();
    assert!(
        html.contains("action=\"https://unsigned.example/acs\""),
        "{html}"
    );
    assert!(html.contains("name=\"RelayState\" value=\"state-1\""));
    let xml = posted_response(&html);
    assert!(xml.contains("InResponseTo=\"_r1\""), "{xml}");
    assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success"));
    // unsigned.example signs assertions (the default behaviour), not responses.
    let doc = parse(&xml, &Limits::default()).unwrap();
    let assertion = doc
        .root
        .elements()
        .find(|e| e.local == "Assertion")
        .unwrap();
    verify(&doc, assertion, &[certificate_der()], DEFAULT_ALLOWED).unwrap();
    assert!(verify(&doc, &doc.root, &[certificate_der()], DEFAULT_ALLOWED).is_err());
    let session_index = |xml: &str| {
        let start = xml.find("SessionIndex=\"").unwrap() + 14;
        xml[start..start + xml[start..].find('"').unwrap()].to_owned()
    };
    let first = session_index(&xml);
    assert_eq!(first.len(), 32);

    // Signed in now: the next request is answered at once, in the same
    // SAML session.
    let query = redirect::encode(
        MessageName::SamlRequest,
        &authn_request("https://unsigned.example", ""),
        None,
        None,
    )
    .unwrap();
    let direct = browser
        .get(format!("{base}/Saml2/SSO{query}"))
        .send()
        .await
        .unwrap();
    assert_eq!(direct.status(), 200);
    let xml = posted_response(&direct.text().await.unwrap());
    assert_eq!(session_index(&xml), first);

    // IsPassive with a session is answered too; ForceAuthn goes to login.
    let force = redirect::encode(
        MessageName::SamlRequest,
        &authn_request("https://unsigned.example", r#" ForceAuthn="true""#),
        None,
        None,
    )
    .unwrap();
    let response = browser
        .get(format!("{base}/Saml2/SSO{force}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
}

#[tokio::test]
async fn passive_requests_without_a_session_get_no_passive() {
    use rustid_saml::bindings::{MessageName, redirect};
    let dir = tempfile::tempdir().unwrap();
    let (base, browser, _stop) = saml_browser_server(dir.path()).await;
    let passive = authn_request("https://unsigned.example", r#" IsPassive="true""#);
    let query = redirect::encode(MessageName::SamlRequest, &passive, None, None).unwrap();
    let response = browser
        .get(format!("{base}/Saml2/SSO{query}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let xml = posted_response(&response.text().await.unwrap());
    assert!(xml.contains(r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoPassive" />"#), "{xml}");
    assert!(!xml.contains("Assertion"));
}

#[tokio::test]
async fn callback_errors() {
    let dir = tempfile::tempdir().unwrap();
    let (base, browser, _stop) = saml_browser_server(dir.path()).await;
    for path in [
        "/Saml2/SSO/Callback",
        "/Saml2/SSO/Callback?samlStateId=nope",
        "/Saml2/SSO/Callback?samlStateId=0192f0a1-2b3c-7d4e-8f90-a1b2c3d4e5f6",
    ] {
        let response = browser.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(response.status(), 302, "{path}");
        assert!(
            response.headers()["location"]
                .to_str()
                .unwrap()
                .starts_with("/home/error?errorId=")
        );
    }
    let response = browser
        .post(format!("{base}/Saml2/SSO/Callback"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 405);
}

#[tokio::test]
async fn custom_sso_paths_route() {
    use rustid_saml::bindings::{MessageName, redirect};
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = saml_sso_server(
        dir.path(),
        serde_json::json!({ "endpoints": { "single_sign_on_service_path": "/custom/sso" } }),
    )
    .await;
    let client = no_redirects();
    let request = authn_request("https://idp-initiated.example", "");
    let query = redirect::encode(MessageName::SamlRequest, &request, None, None).unwrap();
    let response = client
        .get(format!("{base}/custom/sso{query}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    let response = client
        .get(format!("{base}/Saml2/SSO{query}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn cancelling_login_answers_the_sp_with_authn_failed() {
    use rustid_saml::bindings::{MessageName, redirect};
    let dir = tempfile::tempdir().unwrap();
    let (base, browser, _stop) = saml_browser_server_with(dir.path(), true).await;
    let query = redirect::encode(
        MessageName::SamlRequest,
        &authn_request("https://unsigned.example", ""),
        Some("rs"),
        None,
    )
    .unwrap();
    let login = browser
        .get(format!("{base}/Saml2/SSO{query}"))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 303);
    let location = login.headers()["location"].to_str().unwrap().to_owned();
    let return_url = url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "ReturnUrl")
        .unwrap()
        .1
        .into_owned();
    let cancelled = browser
        .post(format!("{base}/account/login"))
        .form(&[("returnUrl", return_url.as_str()), ("button", "cancel")])
        .send()
        .await
        .unwrap();
    assert!(cancelled.status().is_redirection());
    assert_eq!(
        cancelled.headers()["location"].to_str().unwrap(),
        return_url,
        "the denial was accepted: back to the callback"
    );
    let page = follow(
        &browser,
        &base,
        cancelled.headers()["location"].to_str().unwrap().to_owned(),
    )
    .await;
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(html.contains("name=\"RelayState\" value=\"rs\""));
    let xml = posted_response(&html);
    assert!(
        xml.contains(r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" />"#),
        "{xml}"
    );
}

#[tokio::test]
async fn the_callback_login_works_in_a_browser_that_never_saw_the_request() {
    use rustid_saml::bindings::{MessageName, redirect};
    let dir = tempfile::tempdir().unwrap();
    let (base, first, _stop) = saml_browser_server(dir.path()).await;
    let query = redirect::encode(
        MessageName::SamlRequest,
        &authn_request("https://unsigned.example", ""),
        None,
        None,
    )
    .unwrap();
    let login = first
        .get(format!("{base}/Saml2/SSO{query}"))
        .send()
        .await
        .unwrap();
    let location = login.headers()["location"].to_str().unwrap().to_owned();
    let return_url = url::Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "ReturnUrl")
        .unwrap()
        .1
        .into_owned();
    // Another browser (no cookies) opens the callback: sent to login, and
    // its login must lead back to the callback, not a refused continuation.
    let second = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    let page = follow(&second, &base, return_url).await;
    assert_eq!(page.status(), 200, "{:?}", page.headers());
    assert!(posted_response(&page.text().await.unwrap()).contains("status:Success"));
}

/// A signed, redirect-bound LogoutRequest from sp.example (its key).
fn logout_request_url(base: &str, name_id: &str, session_index: &str) -> String {
    use rustid_saml::bindings::{MessageName, redirect};
    let xml = format!(
        r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_lo1" Version="2.0" IssueInstant="{}" Destination="{base}/Saml2/SLO"><saml:Issuer>https://sp.example</saml:Issuer><saml:NameID>{name_id}</saml:NameID><samlp:SessionIndex>{session_index}</samlp:SessionIndex></samlp:LogoutRequest>"#,
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ")
    );
    let credential = sp_credential();
    let signer: &dyn rustid_saml::xml::dsig::XmlSigner = &credential;
    let query = redirect::encode(
        MessageName::SamlRequest,
        &xml,
        Some("slo-state"),
        Some(signer),
    )
    .unwrap();
    format!("{base}/Saml2/SLO{query}")
}

/// The SAML message in a redirect URL, inflated.
fn redirected_message(location: &str) -> String {
    let query = location.split_once('?').unwrap().1;
    rustid_saml::bindings::redirect::parse(query, 1 << 20, 1 << 20)
        .unwrap()
        .xml
}

fn attribute_of(xml: &str, name: &str) -> String {
    let marker = format!("{name}=\"");
    let start = xml.find(&marker).unwrap() + marker.len();
    xml[start..start + xml[start..].find('"').unwrap()].to_owned()
}

#[tokio::test]
async fn slo_without_a_session_answers_success_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let (base, browser, _stop) = saml_browser_server(dir.path()).await;
    let response = browser
        .get(logout_request_url(&base, "x", "y"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    let location = response.headers()["location"].to_str().unwrap().to_owned();
    assert!(
        location.starts_with("https://sp.example/slo?SAMLResponse="),
        "{location}"
    );
    assert!(location.contains("&RelayState=slo-state&SigAlg="));
    let xml = redirected_message(&location);
    assert!(xml.contains(r#"InResponseTo="_lo1""#), "{xml}");
    assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success"));
    // Unsigned requests are refused.
    let unsigned = {
        use rustid_saml::bindings::{MessageName, redirect};
        let request = r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_u" Version="2.0" IssueInstant="2026-10-02T10:00:00Z"><saml:Issuer>https://sp.example</saml:Issuer><saml:NameID>x</saml:NameID></samlp:LogoutRequest>"#;
        redirect::encode(MessageName::SamlRequest, request, None, None).unwrap()
    };
    let refused = browser
        .get(format!("{base}/Saml2/SLO{unsigned}"))
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 302);
    assert!(
        refused.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("/home/error?errorId=")
    );
}

#[tokio::test]
async fn slo_signs_out_notifies_the_other_sps_and_answers() {
    use rustid_saml::bindings::{MessageName, redirect};
    let dir = tempfile::tempdir().unwrap();
    let (base, browser, _stop) = saml_browser_server(dir.path()).await;
    // Signed in at two SPs: unsigned.example, then sp.example (signed request).
    let query = redirect::encode(
        MessageName::SamlRequest,
        &authn_request("https://unsigned.example", ""),
        None,
        None,
    )
    .unwrap();
    follow(&browser, &base, format!("/Saml2/SSO{query}")).await;
    let signed = authn_request(
        "https://sp.example",
        &format!(r#" Destination="{base}/Saml2/SSO""#),
    );
    let credential = sp_credential();
    let signer: &dyn rustid_saml::xml::dsig::XmlSigner = &credential;
    let query = redirect::encode(MessageName::SamlRequest, &signed, None, Some(signer)).unwrap();
    let page = browser
        .get(format!("{base}/Saml2/SSO{query}"))
        .send()
        .await
        .unwrap();
    let xml = posted_response(&page.text().await.unwrap());
    let session_index = attribute_of(&xml, "SessionIndex");
    let name_id = {
        let start = xml.find("<saml:NameID").unwrap();
        let start = start + xml[start..].find('>').unwrap() + 1;
        xml[start..start + xml[start..].find('<').unwrap()].to_owned()
    };

    // sp.example's LogoutRequest leads to the logout page.
    let to_logout = browser
        .get(logout_request_url(&base, &name_id, &session_index))
        .send()
        .await
        .unwrap();
    assert_eq!(to_logout.status(), 303);
    let logout_page = to_logout.headers()["location"].to_str().unwrap().to_owned();
    assert!(
        logout_page.starts_with(&format!("{base}/Account/Logout?logoutId=")),
        "{logout_page}"
    );
    let signed_out = follow(&browser, &base, logout_page).await;
    // The scripted reference UI answers with the logout context it used.
    let context: serde_json::Value = signed_out.json().await.unwrap();
    let iframe = context["signOutIFrameUrl"].as_str().unwrap().to_owned();
    let back = context["postLogoutRedirectUri"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(back.contains("/Saml2/SLO/Callback?logoutId="), "{back}");

    // The end session callback sends unsigned.example a signed LogoutRequest.
    let frames = browser.get(&iframe).send().await.unwrap();
    assert_eq!(frames.status(), 200);
    let csp = frames.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        csp.contains("frame-src https://unsigned.example 'self'"),
        "{csp}"
    );
    let frames = frames.text().await.unwrap();
    let start = frames.find("src='https://unsigned.example/slo?").unwrap() + 5;
    let request_url =
        frames[start..start + frames[start..].find('\'').unwrap()].replace("&amp;", "&");
    assert!(request_url.contains("&SigAlg=") && request_url.contains("&Signature="));
    let request_xml = redirected_message(&request_url);
    let request_id = attribute_of(&request_xml, "ID");
    assert!(
        request_xml.contains("<samlp:SessionIndex>"),
        "{request_xml}"
    );

    // Before unsigned.example answers, the callback would report PartialLogout;
    // its (unsigned, allowed) LogoutResponse is recorded.
    let response_xml = format!(
        r#"<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r" Version="2.0" IssueInstant="2026-10-02T10:00:00Z" InResponseTo="{request_id}"><saml:Issuer>https://unsigned.example</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:LogoutResponse>"#
    );
    let query = redirect::encode(MessageName::SamlResponse, &response_xml, None, None).unwrap();
    let recorded = browser
        .get(format!("{base}/Saml2/SLO{query}"))
        .send()
        .await
        .unwrap();
    assert_eq!(recorded.status(), 200);

    // The callback answers sp.example: Success, its relay state echoed.
    let answer = browser.get(format!("{base}{back}")).send().await.unwrap();
    assert_eq!(answer.status(), 302);
    let location = answer.headers()["location"].to_str().unwrap().to_owned();
    assert!(
        location.starts_with("https://sp.example/slo?SAMLResponse="),
        "{location}"
    );
    assert!(location.contains("RelayState=slo-state"));
    let xml = redirected_message(&location);
    assert!(xml.contains(r#"InResponseTo="_lo1""#));
    assert!(
        xml.contains(r#"<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />"#),
        "{xml}"
    );
}

#[tokio::test]
async fn an_oidc_end_session_logs_out_of_the_saml_sps() {
    use rustid_saml::bindings::{MessageName, redirect};
    let dir = tempfile::tempdir().unwrap();
    let (base, browser, _stop) = saml_browser_server(dir.path()).await;
    // Signed in only through SAML, at unsigned.example.
    let query = redirect::encode(
        MessageName::SamlRequest,
        &authn_request("https://unsigned.example", ""),
        None,
        None,
    )
    .unwrap();
    follow(&browser, &base, format!("/Saml2/SSO{query}")).await;
    // The end session endpoint: the logout page, whose context has the
    // signout iframe for the SAML SP.
    let page = follow(&browser, &base, format!("{base}/connect/endsession")).await;
    let context: serde_json::Value = page.json().await.unwrap();
    let iframe = context["signOutIFrameUrl"]
        .as_str()
        .expect("an iframe for the SAML SP")
        .to_owned();
    let frames = browser.get(&iframe).send().await.unwrap();
    assert_eq!(frames.status(), 200);
    let csp = frames.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        csp.contains("frame-src https://unsigned.example 'self'"),
        "{csp}"
    );
    let html = frames.text().await.unwrap();
    let start = html
        .find("src='https://unsigned.example/slo?")
        .expect(&html)
        + 5;
    let url = html[start..start + html[start..].find('\'').unwrap()].replace("&amp;", "&");
    assert!(url.contains("&SigAlg=") && url.contains("&Signature="));
    assert!(redirected_message(&url).contains("<samlp:LogoutRequest "));
}

/// IdP-initiated SSO as the reference UI's hook drives it: the interaction
/// API checks the SP and the browser's session and hands back a one-time
/// continuation, and the browser's visit there gets the auto-post page.
#[tokio::test]
async fn idp_initiated_sso_through_the_interaction_api() {
    use rustid_saml::bindings::{MessageName, redirect};
    let dir = tempfile::tempdir().unwrap();
    let (base, browser, _stop) = saml_browser_server(dir.path()).await;
    let hook = |sp: &str, relay: &str| {
        format!(
            "{base}/test/saml/idp-initiated?sp={}&relayState={}",
            url::form_urlencoded::byte_serialize(sp.as_bytes()).collect::<String>(),
            url::form_urlencoded::byte_serialize(relay.as_bytes()).collect::<String>()
        )
    };
    let error = |response: reqwest::Response| async move {
        assert_eq!(response.status(), 400);
        let body: serde_json::Value = response.json().await.unwrap();
        body["error"].as_str().unwrap().to_owned()
    };

    // Signed out: the request checks run first, then the user check.
    let signed_out = browser
        .get(hook("https://idp-initiated.example", ""))
        .send()
        .await
        .unwrap();
    assert_eq!(error(signed_out).await, "User is not authenticated");
    let not_allowed = browser
        .get(hook("https://unsigned.example", ""))
        .send()
        .await
        .unwrap();
    assert_eq!(
        error(not_allowed).await,
        "Service provider does not allow IdP-initiated SSO"
    );

    // Signed in (an SP-initiated sign-in to another SP).
    let query = redirect::encode(
        MessageName::SamlRequest,
        &authn_request("https://unsigned.example", ""),
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        follow(&browser, &base, format!("/Saml2/SSO{query}"))
            .await
            .status(),
        200
    );

    let started = browser
        .get(hook("https://idp-initiated.example", "/dashboard"))
        .send()
        .await
        .unwrap();
    assert_eq!(started.status(), 302);
    let continue_url = started.headers()["location"].to_str().unwrap().to_owned();
    assert!(
        continue_url.contains("/connect/interaction/saml/idp-initiated?token="),
        "{continue_url}"
    );
    let page = browser.get(&continue_url).send().await.unwrap();
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(
        html.contains("action=\"https://idp-initiated.example/acs\""),
        "{html}"
    );
    assert!(html.contains("name=\"RelayState\" value=\"/dashboard\""));
    let xml = posted_response(&html);
    assert!(!xml.contains("InResponseTo"), "unsolicited: {xml}");
    assert!(xml.contains("Destination=\"https://idp-initiated.example/acs\""));
    assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:status:Success"));

    // The continuation is one-time.
    let replayed = browser.get(&continue_url).send().await.unwrap();
    assert_eq!(replayed.status(), 400);

    // And bound to the browser's session: another browser can't use it.
    let started = browser
        .get(hook("https://idp-initiated.example", ""))
        .send()
        .await
        .unwrap();
    let continue_url = started.headers()["location"].to_str().unwrap().to_owned();
    let stranger = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let response = stranger.get(&continue_url).send().await.unwrap();
    assert_eq!(error(response).await, "User is not authenticated");

    // Another signed-in browser (its own session) can't use it either.
    let started = browser
        .get(hook("https://idp-initiated.example", ""))
        .send()
        .await
        .unwrap();
    let continue_url = started.headers()["location"].to_str().unwrap().to_owned();
    let other = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .cookie_store(true)
        .build()
        .unwrap();
    assert_eq!(
        follow(&other, &base, format!("/Saml2/SSO{query}"))
            .await
            .status(),
        200
    );
    let response = other.get(&continue_url).send().await.unwrap();
    assert_eq!(error(response).await, "invalid_continuation");

    // Signed out between the API call and the visit: no response.
    let started = browser
        .get(hook("https://idp-initiated.example", ""))
        .send()
        .await
        .unwrap();
    let continue_url = started.headers()["location"].to_str().unwrap().to_owned();
    let signed_out = follow(&browser, &base, format!("{base}/account/logout")).await;
    assert!(signed_out.status().is_success(), "{}", signed_out.status());
    let response = browser.get(&continue_url).send().await.unwrap();
    assert_eq!(error(response).await, "User is not authenticated");
}
