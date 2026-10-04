//! The admin API in the server: off by default, keys required when on,
//! and admin writes visible to the running server at once.

use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

const KEY: &str = "an-admin-api-key-of-at-least-32-chars";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn config(dir: &Path, admin: serde_json::Value) -> ServerConfig {
    let config = serde_json::json!({
        "signing_keys": [{ "kid": "k1", "alg": "RS256", "key_file": fixture("signing-key.pem") }],
        "clients_file": fixture("clients.json"),
        "resources_file": fixture("resources.json"),
        "protocol": { "key_management": { "enabled": false } },
        "admin": admin,
    });
    let path = dir.join("rustid.json");
    std::fs::write(&path, config.to_string()).unwrap();
    ServerConfig::load(Some(&path)).unwrap()
}

async fn start(config: &ServerConfig) -> (String, tokio::sync::oneshot::Sender<()>) {
    let app = rustid_server::build(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(rustid_server::serve(listener, app, async move {
        let _ = stopped.await;
    }));
    (base, stop)
}

#[tokio::test]
async fn the_admin_api_is_off_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(&config(dir.path(), serde_json::json!({}))).await;
    let response = reqwest::Client::new()
        .get(format!("{base}/admin/api-scopes"))
        .bearer_auth(KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn enabling_it_needs_long_keys() {
    let dir = tempfile::tempdir().unwrap();
    for admin in [
        serde_json::json!({ "enabled": true }),
        serde_json::json!({ "enabled": true, "api_keys": ["too-short"] }),
    ] {
        assert!(
            rustid_server::build(&config(dir.path(), admin.clone()))
                .await
                .is_err(),
            "{admin}"
        );
    }
}

#[tokio::test]
async fn admin_writes_reach_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(&config(
        dir.path(),
        serde_json::json!({ "enabled": true, "api_keys": [KEY] }),
    ))
    .await;
    let client = reqwest::Client::new();
    let created = client
        .post(format!("{base}/admin/api-scopes"))
        .bearer_auth(KEY)
        .json(&serde_json::json!({ "name": "admin_made" }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let discovery: serde_json::Value = client
        .get(format!("{base}/.well-known/openid-configuration"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let scopes = discovery["scopes_supported"].as_array().unwrap();
    assert!(scopes.iter().any(|s| s == "admin_made"), "{scopes:?}");
}

/// An API resource and its secret made by admin authenticate at
/// introspection straight away.
#[tokio::test]
async fn admin_made_api_secrets_authenticate_at_introspection() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(&config(
        dir.path(),
        serde_json::json!({ "enabled": true, "api_keys": [KEY] }),
    ))
    .await;
    let client = reqwest::Client::new();
    let admin = |path: &str, body: serde_json::Value| {
        client
            .post(format!("{base}/admin/{path}"))
            .bearer_auth(KEY)
            .json(&body)
            .send()
    };
    admin("api-scopes", serde_json::json!({ "name": "orders" }))
        .await
        .unwrap();
    let created: serde_json::Value = admin(
        "api-resources",
        serde_json::json!({ "name": "orders-api", "scopes": ["orders"] }),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let introspect = || {
        client
            .post(format!("{base}/connect/introspect"))
            .basic_auth("orders-api", Some("orders-secret"))
            .form(&[("token", "not-a-token")])
            .send()
    };
    assert_eq!(introspect().await.unwrap().status(), 401, "no secret yet");
    let id = created["id"].as_str().unwrap();
    let secret = admin(
        &format!("api-resources/{id}/secrets"),
        serde_json::json!({ "plaintextValue": "orders-secret" }),
    )
    .await
    .unwrap();
    assert_eq!(secret.status(), 201);
    assert_eq!(introspect().await.unwrap().status(), 200);
}

#[tokio::test]
async fn admin_made_clients_get_tokens_and_cors_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let (base, _stop) = start(&config(
        dir.path(),
        serde_json::json!({ "enabled": true, "api_keys": [KEY] }),
    ))
    .await;
    let http = reqwest::Client::new();
    let token = |secret: &'static str| {
        let http = http.clone();
        let base = base.clone();
        async move {
            http.post(format!("{base}/connect/token"))
                .basic_auth("admin-made", Some(secret))
                .form(&[("grant_type", "client_credentials"), ("scope", "api1")])
                .send()
                .await
                .unwrap()
        }
    };
    let preflight = |origin: &'static str| {
        let http = http.clone();
        let base = base.clone();
        async move {
            http.request(reqwest::Method::OPTIONS, format!("{base}/connect/token"))
                .header("origin", origin)
                .header("access-control-request-method", "POST")
                .send()
                .await
                .unwrap()
                .headers()
                .get("access-control-allow-origin")
                .map(|v| v.to_str().unwrap().to_owned())
        }
    };
    assert_eq!(token("admin-secret").await.status(), 400);

    let created = http
        .post(format!("{base}/admin/clients"))
        .bearer_auth(KEY)
        .json(&serde_json::json!({
            "clientId": "admin-made",
            "allowedGrantTypes": ["client_credentials"],
            "allowedScopes": ["api1"],
            "allowedCorsOrigins": ["https://spa.example"],
            "clientSecrets": [{ "plaintextValue": "admin-secret" }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let id = created.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let issued = token("admin-secret").await;
    assert_eq!(issued.status(), 200);
    assert!(issued.json::<serde_json::Value>().await.unwrap()["access_token"].is_string());
    assert_eq!(token("wrong").await.status(), 400);
    assert_eq!(
        preflight("https://spa.example").await.as_deref(),
        Some("https://spa.example")
    );

    // An origin removed by admin is refused at once.
    let mut read: serde_json::Value = http
        .get(format!("{base}/admin/clients/{id}"))
        .bearer_auth(KEY)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    read["allowedCorsOrigins"] = serde_json::json!(["https://other.example"]);
    let updated = http
        .put(format!("{base}/admin/clients/{id}"))
        .bearer_auth(KEY)
        .header("if-match", "\"1\"")
        .json(&read)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), 200);
    assert_eq!(preflight("https://spa.example").await, None);
    assert_eq!(
        preflight("https://other.example").await.as_deref(),
        Some("https://other.example")
    );
    // The update kept the secret.
    assert_eq!(token("admin-secret").await.status(), 200);
}

#[tokio::test]
async fn schemas_file_registers_read_only_schemas() {
    let dir = tempfile::tempdir().unwrap();
    let schemas = dir.path().join("schemas.json");
    std::fs::write(
        &schemas,
        serde_json::json!([{
            "schemaId": "api-scope",
            "attributeDefinitions": [
                { "code": "owner", "attributeType": { "kind": "scalar", "dataType": "String" } },
            ],
        }])
        .to_string(),
    )
    .unwrap();
    let admin = serde_json::json!({ "enabled": true, "api_keys": [KEY], "schemas_file": schemas });
    let (base, _stop) = start(&config(dir.path(), admin.clone())).await;
    let http = reqwest::Client::new();
    let read = http
        .get(format!("{base}/admin/schemas/api-scope"))
        .bearer_auth(KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(read.status(), 200);
    let refused = http
        .delete(format!("{base}/admin/schemas/api-scope"))
        .bearer_auth(KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(refused.status(), 405);
    let created = http
        .post(format!("{base}/admin/api-scopes"))
        .bearer_auth(KEY)
        .json(&serde_json::json!({
            "name": "owned", "extendedProperties": { "owner": "platform-team" },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    // A schema the file gets wrong stops the server starting.
    std::fs::write(&schemas, r#"[{ "schemaId": "a.b" }]"#).unwrap();
    let error = rustid_server::build(&config(dir.path(), admin))
        .await
        .err()
        .expect("a bad schema refuses to start");
    assert!(
        format!("{error:#}").contains("Must match the required pattern."),
        "{error:#}"
    );
}

#[tokio::test]
async fn schemas_file_is_the_registered_set() {
    use rustid_core::admin::schemas::{SchemaAdmin, SchemaConfiguration};
    let store = rustid_store_memory::InMemoryConfiguration::new(
        &Default::default(),
        &rustid_core::resources::Resources::default(),
    );
    for id in ["client", "api-scope"] {
        let schema = SchemaConfiguration {
            schema_id: id.into(),
            ..Default::default()
        };
        SchemaAdmin.create(&store, schema).await.unwrap().unwrap();
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("schemas.json");
    std::fs::write(
        &file,
        r#"[{ "schemaId": "API-SCOPE", "displayName": "Scopes" }]"#,
    )
    .unwrap();
    rustid_server::register_schemas(&store, &file)
        .await
        .unwrap();
    let ids: Vec<String> = SchemaAdmin
        .query(&store)
        .await
        .unwrap()
        .into_iter()
        .map(|s| s.schema_id)
        .collect();
    assert_eq!(
        ids,
        ["API-SCOPE"],
        "a schema absent from the file is removed"
    );
}

/// A SAML service provider made, disabled and deleted by admin is served,
/// refused and forgotten at once.
#[cfg(feature = "saml")]
#[tokio::test]
async fn admin_made_saml_service_providers_sign_in_at_once() {
    use rustid_saml::bindings::MessageName;
    use rustid_saml::bindings::redirect;

    let dir = tempfile::tempdir().unwrap();
    let mut config = config(
        dir.path(),
        serde_json::json!({ "enabled": true, "api_keys": [KEY] }),
    );
    config.saml.enabled = true;
    let (base, _stop) = start(&config).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let entity_id = "https://admin-made.example";
    // A fresh AuthnRequest each time; where the IdP sends the browser.
    let sign_in = || async {
        let xml = format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_{}" Version="2.0" IssueInstant="{}"><saml:Issuer>{entity_id}</saml:Issuer></samlp:AuthnRequest>"#,
            rustid_saml::ids::create_id(),
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        );
        let query = redirect::encode(MessageName::SamlRequest, &xml, None, None).unwrap();
        let response = client
            .get(format!("{base}/Saml2/SSO{query}"))
            .send()
            .await
            .unwrap();
        (
            response.status().as_u16(),
            response
                .headers()
                .get("location")
                .map(|l| l.to_str().unwrap().to_owned())
                .unwrap_or_default(),
        )
    };
    let refused = sign_in().await;
    assert_eq!(refused.0, 302, "an unknown SP goes to the error page");
    assert!(!refused.1.contains("Saml2/SSO/Callback"), "{}", refused.1);

    let body = serde_json::json!({
        "entityId": entity_id,
        "assertionConsumerServiceUrls": [
            { "location": "https://admin-made.example/acs", "binding": "HttpPost", "index": 0, "isDefault": true }
        ],
        "allowedScopes": ["openid"],
        "requireSignedAuthnRequests": false,
    });
    let created: serde_json::Value = client
        .post(format!("{base}/admin/saml-service-providers"))
        .bearer_auth(KEY)
        .json(&body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["id"].as_str().unwrap().to_owned();
    let login = sign_in().await;
    assert_eq!(login.0, 303, "{}", login.1);
    assert!(
        login.1.contains("Saml2%2FSSO%2FCallback") || login.1.contains("Saml2/SSO/Callback"),
        "{}",
        login.1
    );

    let mut disabled = body.clone();
    disabled["enabled"] = serde_json::json!(false);
    let updated = client
        .put(format!("{base}/admin/saml-service-providers/{id}"))
        .bearer_auth(KEY)
        .header("if-match", "\"1\"")
        .json(&disabled)
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), 200);
    assert_eq!(sign_in().await.0, 302, "a disabled SP is refused at once");

    let deleted = client
        .delete(format!("{base}/admin/saml-service-providers/{id}"))
        .bearer_auth(KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 204);
    assert_eq!(sign_in().await.0, 302);
}
