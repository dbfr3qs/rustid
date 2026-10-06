//! The admin HTTP API: authentication, the resource routes, versions and
//! errors.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::BodyExt;
use rustid_admin::{AdminState, router};
use rustid_core::resources::Resources;
use rustid_store_memory::InMemoryConfiguration;
use serde_json::{Value, json};
use tower::ServiceExt;

const KEY: &str = "an-admin-api-key-of-at-least-32-chars";

fn app() -> axum::Router {
    app_with(false)
}

fn app_with(schemas_read_only: bool) -> axum::Router {
    router(AdminState {
        configuration: Arc::new(InMemoryConfiguration::new(
            &Default::default(),
            &Resources::default(),
        )),
        api_keys: vec![KEY.to_owned()],
        clients: Default::default(),
        schemas_read_only,
        identity_providers: Arc::new(
            rustid_core::admin::identity_providers::IdentityProviderAdmin::new(Arc::new(
                rustid_core::data_protection::DataProtector::new([("k", [3u8; 32].as_slice())])
                    .unwrap(),
            )),
        ),
    })
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

async fn call(
    app: &axum::Router,
    method: Method,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> Reply {
    let mut request = Request::builder().method(method).uri(path);
    let mut authorized = false;
    for (k, v) in headers {
        authorized |= k.eq_ignore_ascii_case("authorization");
        request = request.header(*k, *v);
    }
    if !authorized {
        request = request.header("authorization", format!("Bearer {KEY}"));
    }
    let body = match body {
        Some(json) => {
            request = request.header("content-type", "application/json");
            Body::from(json.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    Reply {
        status,
        headers,
        body: if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        },
    }
}

fn first_error(reply: &Reply) -> (&str, &Value) {
    let error = &reply.body["errors"][0];
    (error["code"].as_str().unwrap(), &error["propertyNames"])
}

#[tokio::test]
async fn requests_need_an_api_key() {
    let app = app();
    for auth in [
        None,
        Some("Bearer wrong"),
        Some("Bearer "),
        Some(&format!("Basic {KEY}")[..]),
        Some(&format!("Bearer {}", &KEY[..10])[..]),
    ] {
        let mut request = Request::get("/admin/api-scopes");
        if let Some(auth) = auth {
            request = request.header("authorization", auth);
        } else {
            request = request.header("x-none", "1");
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{auth:?}");
        assert_eq!(response.headers()["www-authenticate"], "Bearer");
    }
}

#[tokio::test]
async fn api_scopes_round_trip_with_versions() {
    let app = app();
    let created = call(
        &app,
        Method::POST,
        "/admin/api-scopes",
        Some(json!({ "name": "s1" })),
        &[],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    assert_eq!(created.body["version"], 1);
    let id = created.body["id"].as_str().unwrap().to_owned();

    let got = call(
        &app,
        Method::GET,
        &format!("/admin/api-scopes/{id}"),
        None,
        &[],
    )
    .await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.headers["etag"], "\"1\"");
    assert_eq!(got.body["name"], "s1");
    assert_eq!(got.body["showInDiscoveryDocument"], true);
    assert_eq!(got.body["id"], id.as_str());
    let by_name = call(&app, Method::GET, "/admin/api-scopes/by-name/s1", None, &[]).await;
    assert_eq!(by_name.body["id"], id.as_str());

    // Updates need If-Match; the body read back can be sent back.
    let mut edit = got.body.clone();
    edit["displayName"] = json!("Scope one");
    let path = format!("/admin/api-scopes/{id}");
    let missing = call(&app, Method::PUT, &path, Some(edit.clone()), &[]).await;
    assert_eq!(missing.status, StatusCode::PRECONDITION_REQUIRED);
    let updated = call(
        &app,
        Method::PUT,
        &path,
        Some(edit.clone()),
        &[("if-match", "\"1\"")],
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK);
    assert_eq!(updated.body["version"], 2);
    let stale = call(
        &app,
        Method::PUT,
        &path,
        Some(edit),
        &[("if-match", "\"1\"")],
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(first_error(&stale).0, "version_conflict");

    // Errors.
    let duplicate = call(
        &app,
        Method::POST,
        "/admin/api-scopes",
        Some(json!({ "name": "s1" })),
        &[],
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    assert_eq!(first_error(&duplicate).0, "already_exists");
    let empty = call(
        &app,
        Method::POST,
        "/admin/api-scopes",
        Some(json!({ "name": "" })),
        &[],
    )
    .await;
    assert_eq!(empty.status, StatusCode::BAD_REQUEST);
    assert_eq!(first_error(&empty), ("required", &json!(["Name"])));
    let unknown = call(
        &app,
        Method::POST,
        "/admin/api-scopes",
        Some(json!({ "name": "s2", "bogus": 1 })),
        &[],
    )
    .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);
    for missing in [
        "/admin/api-scopes/0192e1f2-0000-7000-8000-000000000000",
        "/admin/api-scopes/not-an-id",
        "/admin/api-scopes/by-name/nothing",
    ] {
        assert_eq!(
            call(&app, Method::GET, missing, None, &[]).await.status,
            StatusCode::NOT_FOUND,
            "{missing}"
        );
    }

    // Delete is idempotent.
    assert_eq!(
        call(&app, Method::DELETE, &path, None, &[]).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, Method::DELETE, &path, None, &[]).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, Method::GET, &path, None, &[]).await.status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn queries_filter_sort_and_page() {
    let app = app();
    for (name, enabled) in [
        ("q-a", true),
        ("q-b", false),
        ("q-c", true),
        ("other", true),
    ] {
        call(
            &app,
            Method::POST,
            "/admin/identity-resources",
            Some(json!({ "name": name, "enabled": enabled })),
            &[],
        )
        .await;
    }
    let page = call(
        &app,
        Method::GET,
        "/admin/identity-resources?name=q-&enabled=true&sort=name&direction=desc&page=1&pageSize=1",
        None,
        &[],
    )
    .await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(page.body["totalCount"], 2);
    assert_eq!(page.body["items"][0]["name"], "q-c");
    assert_eq!(page.body["hasMoreData"], true);
    let next = page.body["nextToken"].as_str().unwrap();
    let following = call(
        &app,
        Method::GET,
        &format!("/admin/identity-resources?name=q-&enabled=true&sort=name&direction=desc&pageSize=1&continuationToken={next}"),
        None,
        &[],
    )
    .await;
    assert_eq!(following.body["items"][0]["name"], "q-a");
    for bad in [
        "pageSize=0",
        "pageSize=1001",
        "sort=bogus",
        "direction=up",
        "continuationToken=!!",
        "enabled=maybe",
    ] {
        let reply = call(
            &app,
            Method::GET,
            &format!("/admin/identity-resources?{bad}"),
            None,
            &[],
        )
        .await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{bad}");
    }
}

#[tokio::test]
async fn null_lists_mean_empty() {
    let app = app();
    let created = call(
        &app,
        Method::POST,
        "/admin/identity-resources",
        Some(json!({ "name": "n", "userClaims": null, "extendedProperties": null })),
        &[],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
}

#[tokio::test]
async fn api_resources_and_their_secrets() {
    let app = app();
    call(
        &app,
        Method::POST,
        "/admin/api-scopes",
        Some(json!({ "name": "orders" })),
        &[],
    )
    .await;
    let created = call(
        &app,
        Method::POST,
        "/admin/api-resources",
        Some(json!({ "name": "orders-api", "scopes": ["orders"] })),
        &[],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED);
    let id = created.body["id"].as_str().unwrap().to_owned();
    let path = format!("/admin/api-resources/{id}");

    let secret = call(
        &app,
        Method::POST,
        &format!("{path}/secrets"),
        Some(json!({ "plaintextValue": "orders-secret", "hashAlgorithm": "Sha512", "description": "main" })),
        &[],
    )
    .await;
    assert_eq!(secret.status, StatusCode::CREATED);
    assert_eq!(secret.body["version"], 2);
    let secret_id = secret.body["id"].as_str().unwrap().to_owned();

    let got = call(&app, Method::GET, &path, None, &[]).await;
    assert_eq!(got.headers["etag"], "\"2\"");
    assert_eq!(got.body["apiSecrets"][0]["id"], secret_id.as_str());
    assert_eq!(got.body["apiSecrets"][0]["description"], "main");
    assert!(got.body["apiSecrets"][0].get("value").is_none());
    assert!(!got.body.to_string().contains("orders-secret"));

    // The body read back can be sent back; secrets are kept.
    let mut edit = got.body.clone();
    edit["displayName"] = json!("Orders");
    let updated = call(
        &app,
        Method::PUT,
        &path,
        Some(edit),
        &[("if-match", "\"2\"")],
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK);
    let after = call(&app, Method::GET, &path, None, &[]).await;
    assert_eq!(after.body["apiSecrets"][0]["id"], secret_id.as_str());

    let by_scope = call(
        &app,
        Method::GET,
        "/admin/api-resources?scope=orders",
        None,
        &[],
    )
    .await;
    assert_eq!(by_scope.body["items"][0]["name"], "orders-api");
    assert_eq!(by_scope.body["items"][0]["scopeCount"], 1);
    let missing_scope = call(
        &app,
        Method::POST,
        "/admin/api-resources",
        Some(json!({ "name": "x", "scopes": ["nope"] })),
        &[],
    )
    .await;
    assert_eq!(missing_scope.status, StatusCode::BAD_REQUEST);
    let empty_secret = call(
        &app,
        Method::POST,
        &format!("{path}/secrets"),
        Some(json!({ "plaintextValue": "" })),
        &[],
    )
    .await;
    assert_eq!(empty_secret.status, StatusCode::BAD_REQUEST);

    let deleted = call(
        &app,
        Method::DELETE,
        &format!("{path}/secrets/{secret_id}"),
        None,
        &[],
    )
    .await;
    assert_eq!(deleted.status, StatusCode::OK);
    assert_eq!(deleted.body["version"], 4);
    let again = call(
        &app,
        Method::DELETE,
        &format!("{path}/secrets/{secret_id}"),
        None,
        &[],
    )
    .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(first_error(&again).0, "not_found");
}

#[tokio::test]
async fn clients_and_their_secrets() {
    let app = app();
    let created = call(
        &app,
        Method::POST,
        "/admin/clients",
        Some(json!({
            "clientId": "machine",
            "clientName": "Machine",
            "allowedGrantTypes": ["client_credentials"],
            "allowedScopes": ["api1"],
            "redirectUris": null,
            "clientSecrets": [{ "plaintextValue": "first", "description": "one" }],
        })),
        &[],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["version"], 1);
    let id = created.body["id"].as_str().unwrap().to_owned();

    let read = call(
        &app,
        Method::GET,
        &format!("/admin/clients/{id}"),
        None,
        &[],
    )
    .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.headers["etag"], "\"1\"");
    assert_eq!(read.body["clientId"], "machine");
    assert_eq!(read.body["id"], id);
    assert_eq!(read.body["clientSecrets"][0]["description"], "one");
    assert!(read.body["clientSecrets"][0].get("value").is_none());
    assert!(!read.body.to_string().contains("first"));
    let by_client_id = call(
        &app,
        Method::GET,
        "/admin/clients/by-client-id/machine",
        None,
        &[],
    )
    .await;
    assert_eq!(by_client_id.body["id"], id);

    // The read sent back, changed, is an update; its secrets are ignored.
    let mut body = read.body.clone();
    body["clientName"] = json!("Renamed");
    let updated = call(
        &app,
        Method::PUT,
        &format!("/admin/clients/{id}"),
        Some(body.clone()),
        &[("if-match", "\"1\"")],
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.body);
    assert_eq!(updated.body["version"], 2);
    let stale = call(
        &app,
        Method::PUT,
        &format!("/admin/clients/{id}"),
        Some(body.clone()),
        &[("if-match", "\"1\"")],
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    let mut unknown = body.clone();
    unknown["noSuchSetting"] = json!(1);
    let refused = call(
        &app,
        Method::PUT,
        &format!("/admin/clients/{id}"),
        Some(unknown),
        &[("if-match", "\"2\"")],
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        first_error(&refused),
        ("invalid_value", &json!(["noSuchSetting"]))
    );
    let invalid = call(
        &app,
        Method::POST,
        "/admin/clients",
        Some(json!({ "clientId": "web", "allowedGrantTypes": ["authorization_code"] })),
        &[],
    )
    .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        invalid.body["errors"][0]["message"],
        "No redirect URI configured."
    );
    let duplicate = call(
        &app,
        Method::POST,
        "/admin/clients",
        Some(json!({
            "clientId": "machine",
            "allowedGrantTypes": ["client_credentials"],
            "clientSecrets": [{ "plaintextValue": "x" }],
        })),
        &[],
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);

    // Secrets.
    let secret = call(
        &app,
        Method::POST,
        &format!("/admin/clients/{id}/secrets"),
        Some(json!({ "plaintextValue": "second", "hashAlgorithm": "Sha512" })),
        &[],
    )
    .await;
    assert_eq!(secret.status, StatusCode::CREATED, "{}", secret.body);
    assert_eq!(secret.body["version"], 3);
    let secret_id = secret.body["id"].as_str().unwrap().to_owned();
    let read = call(
        &app,
        Method::GET,
        &format!("/admin/clients/{id}"),
        None,
        &[],
    )
    .await;
    assert_eq!(read.body["clientSecrets"].as_array().unwrap().len(), 2);
    let path = format!("/admin/clients/{id}/secrets/{secret_id}");
    assert_eq!(
        call(&app, Method::DELETE, &path, None, &[]).await.status,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, Method::DELETE, &path, None, &[]).await.status,
        StatusCode::NOT_FOUND
    );

    // Query.
    let listed = call(
        &app,
        Method::GET,
        "/admin/clients?grantType=client_credentials&clientName=Ren&sort=clientId&direction=desc",
        None,
        &[],
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    assert_eq!(listed.body["totalCount"], 1);
    assert_eq!(listed.body["items"][0]["clientId"], "machine");
    assert_eq!(listed.body["items"][0]["allowedScopeCount"], 1);
    let none = call(
        &app,
        Method::GET,
        "/admin/clients?allowedScope=nope&enabled=true",
        None,
        &[],
    )
    .await;
    assert_eq!(none.body["totalCount"], 0);
    let bad_sort = call(&app, Method::GET, "/admin/clients?sort=name", None, &[]).await;
    assert_eq!(bad_sort.status, StatusCode::BAD_REQUEST);

    assert_eq!(
        call(
            &app,
            Method::DELETE,
            &format!("/admin/clients/{id}"),
            None,
            &[]
        )
        .await
        .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(
            &app,
            Method::GET,
            &format!("/admin/clients/{id}"),
            None,
            &[]
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );
}

fn client_schema() -> Value {
    json!({
        "schemaId": "client",
        "displayName": "Client",
        "attributeDefinitions": [
            { "code": "department", "attributeType": { "kind": "scalar", "dataType": "String" } },
            { "code": "cost_center", "attributeType": { "kind": "scalar", "dataType": "Integer" } },
        ],
    })
}

#[tokio::test]
async fn schemas_and_extended_properties() {
    let app = app();
    let client = json!({
        "clientId": "tagged",
        "allowedGrantTypes": ["client_credentials"],
        "clientSecrets": [{ "plaintextValue": "s" }],
        "extendedProperties": { "department": "Engineering", "cost_center": 1042 },
    });
    let refused = call(
        &app,
        Method::POST,
        "/admin/clients",
        Some(client.clone()),
        &[],
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        refused.body["errors"][0]["message"],
        "Attribute 'department' is not defined in the schema.; \
         Attribute 'cost_center' is not defined in the schema."
    );

    let created = call(
        &app,
        Method::POST,
        "/admin/schemas",
        Some(client_schema()),
        &[],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    assert_eq!(created.body["version"], 1);
    let duplicate = call(
        &app,
        Method::POST,
        "/admin/schemas",
        Some(client_schema()),
        &[],
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    let read = call(&app, Method::GET, "/admin/schemas/CLIENT", None, &[]).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.headers["etag"], "\"1\"");
    assert_eq!(read.body["schemaId"], "client");
    assert_eq!(
        read.body["attributeDefinitions"][1]["attributeType"]["dataType"],
        "Integer"
    );
    let listed = call(&app, Method::GET, "/admin/schemas", None, &[]).await;
    assert_eq!(listed.body["items"][0]["attributeCount"], 2);
    assert_eq!(listed.body["totalCount"], 1);

    let mut twice = client.clone();
    twice["clientId"] = json!("twice");
    twice["extendedProperties"] = json!({ "department": "a", "Department": "b" });
    let refused = call(&app, Method::POST, "/admin/clients", Some(twice), &[]).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        refused.body["errors"][0]["message"],
        "The attributes contain more than one attribute named 'Department'."
    );
    let tagged = call(&app, Method::POST, "/admin/clients", Some(client), &[]).await;
    assert_eq!(tagged.status, StatusCode::CREATED, "{}", tagged.body);
    let id = tagged.body["id"].as_str().unwrap().to_owned();
    let read_client = call(
        &app,
        Method::GET,
        &format!("/admin/clients/{id}"),
        None,
        &[],
    )
    .await;
    assert_eq!(
        read_client.body["extendedProperties"],
        json!({ "department": "Engineering", "cost_center": 1042 })
    );
    assert!(read_client.body.get("properties").is_none());
    let mut with_properties = read_client.body.clone();
    with_properties["properties"] = json!({ "department": "x" });
    let unknown = call(
        &app,
        Method::PUT,
        &format!("/admin/clients/{id}"),
        Some(with_properties),
        &[("if-match", "\"1\"")],
    )
    .await;
    assert_eq!(unknown.status, StatusCode::BAD_REQUEST);

    // Updates need If-Match and the route's id.
    let mut schema = client_schema();
    schema["description"] = json!("changed");
    let no_match = call(
        &app,
        Method::PUT,
        "/admin/schemas/client",
        Some(schema.clone()),
        &[],
    )
    .await;
    assert_eq!(no_match.status, StatusCode::PRECONDITION_REQUIRED);
    let other = call(
        &app,
        Method::PUT,
        "/admin/schemas/other",
        Some(schema.clone()),
        &[("if-match", "\"1\"")],
    )
    .await;
    assert_eq!(other.status, StatusCode::BAD_REQUEST);
    let updated = call(
        &app,
        Method::PUT,
        "/admin/schemas/client",
        Some(schema.clone()),
        &[("if-match", "\"1\"")],
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.body);
    assert_eq!(updated.body["version"], 2);
    let stale = call(
        &app,
        Method::PUT,
        "/admin/schemas/client",
        Some(schema),
        &[("if-match", "\"1\"")],
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    let invalid = call(
        &app,
        Method::POST,
        "/admin/schemas",
        Some(json!({ "schemaId": "a.b" })),
        &[],
    )
    .await;
    assert_eq!(
        first_error(&invalid),
        ("invalid_value", &json!(["SchemaId"]))
    );

    assert_eq!(
        call(&app, Method::DELETE, "/admin/schemas/client", None, &[])
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, Method::GET, "/admin/schemas/client", None, &[])
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn read_only_schemas_refuse_writes() {
    let app = app_with(true);
    for (method, path, body) in [
        (Method::POST, "/admin/schemas", Some(client_schema())),
        (Method::PUT, "/admin/schemas/client", Some(client_schema())),
        (Method::DELETE, "/admin/schemas/client", None),
    ] {
        let reply = call(&app, method.clone(), path, body, &[("if-match", "\"1\"")]).await;
        assert_eq!(
            reply.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}"
        );
        assert_eq!(
            reply.body["errors"][0]["message"],
            "Schemas are read-only: they come from schemas_file."
        );
        assert_eq!(reply.headers["allow"], "GET", "{method} {path}");
    }
    assert_eq!(
        call(&app, Method::GET, "/admin/schemas", None, &[])
            .await
            .status,
        StatusCode::OK
    );
}

#[cfg(feature = "saml")]
#[tokio::test]
async fn saml_service_providers() {
    let app = app();
    let path = "/admin/saml-service-providers";
    let sp = |entity_id: &str| {
        json!({
            "entityId": entity_id,
            "displayName": "Shop",
            "assertionConsumerServiceUrls": [
                { "location": "https://shop.example/acs", "binding": "HttpPost", "index": 0, "isDefault": true }
            ],
            "allowedScopes": ["openid"],
            "certificates": null,
        })
    };
    let created = call(
        &app,
        Method::POST,
        path,
        Some(sp("https://shop.example")),
        &[],
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let id = created.body["id"].as_str().unwrap().to_owned();

    let read = call(&app, Method::GET, &format!("{path}/{id}"), None, &[]).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.headers["etag"], "\"1\"");
    assert_eq!(read.body["entityId"], "https://shop.example");
    assert_eq!(read.body["id"], id);
    let by_entity = call(
        &app,
        Method::GET,
        &format!("{path}/by-entity-id/https%3A%2F%2Fshop.example"),
        None,
        &[],
    )
    .await;
    assert_eq!(by_entity.status, StatusCode::OK);
    assert_eq!(by_entity.body["id"], id);
    assert_eq!(
        call(
            &app,
            Method::GET,
            &format!("{path}/by-entity-id/nobody"),
            None,
            &[]
        )
        .await
        .status,
        StatusCode::NOT_FOUND
    );

    // The read sent back, changed, is an update.
    let mut body = read.body.clone();
    body["displayName"] = json!("Renamed");
    let updated = call(
        &app,
        Method::PUT,
        &format!("{path}/{id}"),
        Some(body.clone()),
        &[("if-match", "\"1\"")],
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.body);
    assert_eq!(updated.body["version"], 2);
    let stale = call(
        &app,
        Method::PUT,
        &format!("{path}/{id}"),
        Some(body.clone()),
        &[("if-match", "\"1\"")],
    )
    .await;
    assert_eq!(stale.status, StatusCode::PRECONDITION_FAILED);
    assert_eq!(
        call(&app, Method::PUT, &format!("{path}/{id}"), Some(body), &[])
            .await
            .status,
        StatusCode::PRECONDITION_REQUIRED
    );

    // Refusals.
    let duplicate = call(
        &app,
        Method::POST,
        path,
        Some(sp("https://shop.example")),
        &[],
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);
    let mut bad = sp("https://bad.example");
    bad["assertionConsumerServiceUrls"][0]["location"] = json!("relative/acs");
    let bad = call(&app, Method::POST, path, Some(bad), &[]).await;
    assert_eq!(bad.status, StatusCode::BAD_REQUEST);
    assert_eq!(
        first_error(&bad),
        ("invalid_value", &json!(["AssertionConsumerServiceUrls"]))
    );
    assert_eq!(
        bad.body["errors"][0]["message"],
        "ACS endpoint location 'relative/acs' is not a valid absolute URI."
    );
    let mut unknown = sp("https://unknown.example");
    unknown["nope"] = json!(true);
    assert_eq!(
        first_error(&call(&app, Method::POST, path, Some(unknown), &[]).await).0,
        "invalid_value"
    );

    // Queries.
    call(
        &app,
        Method::POST,
        path,
        Some(sp("https://another.example")),
        &[],
    )
    .await;
    let listed = call(
        &app,
        Method::GET,
        &format!("{path}?entityId=example&sort=entityId&direction=desc"),
        None,
        &[],
    )
    .await;
    assert_eq!(listed.status, StatusCode::OK, "{}", listed.body);
    let ids: Vec<&str> = listed.body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["entityId"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["https://shop.example", "https://another.example"]);
    assert_eq!(listed.body["items"][0]["allowedScopeCount"], 1);
    let renamed = call(
        &app,
        Method::GET,
        &format!("{path}?displayName=Renamed"),
        None,
        &[],
    )
    .await;
    assert_eq!(renamed.body["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        call(&app, Method::GET, &format!("{path}?sort=bogus"), None, &[])
            .await
            .status,
        StatusCode::BAD_REQUEST
    );

    // Deletes are idempotent.
    for _ in 0..2 {
        assert_eq!(
            call(&app, Method::DELETE, &format!("{path}/{id}"), None, &[])
                .await
                .status,
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        call(&app, Method::GET, &format!("{path}/{id}"), None, &[])
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn identity_providers_over_http_never_show_their_secret() {
    let app = app();
    let auth = format!("Bearer {KEY}");
    let headers = [("authorization", auth.as_str())];
    let provider = json!({
        "scheme": "corp", "displayName": "Corp", "authority": "https://login.corp.example",
        "clientId": "rustid", "clientAuthentication": { "secret": "top-secret-value" },
    });
    let created = call(
        &app,
        Method::POST,
        "/admin/identity-providers",
        Some(provider.clone()),
        &headers,
    )
    .await;
    assert_eq!(created.status, StatusCode::CREATED, "{}", created.body);
    let id = created.body["id"].as_str().unwrap().to_owned();
    assert!(!created.body.to_string().contains("top-secret-value"));

    let read = call(
        &app,
        Method::GET,
        &format!("/admin/identity-providers/{id}"),
        None,
        &headers,
    )
    .await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(read.body["scheme"], "corp");
    assert_eq!(read.body["clientAuthentication"]["hasSecret"], true);
    assert!(
        !read.body.to_string().contains("top-secret-value"),
        "{}",
        read.body
    );
    let etag = read.headers["etag"].to_str().unwrap().to_owned();

    let by_scheme = call(
        &app,
        Method::GET,
        "/admin/identity-providers/by-scheme/corp",
        None,
        &headers,
    )
    .await;
    assert_eq!(by_scheme.body["id"], id.as_str());
    let list = call(
        &app,
        Method::GET,
        "/admin/identity-providers?displayName=Co",
        None,
        &headers,
    )
    .await;
    assert_eq!(list.body["items"][0]["scheme"], "corp");
    assert!(!list.body.to_string().contains("top-secret-value"));

    let duplicate = call(
        &app,
        Method::POST,
        "/admin/identity-providers",
        Some(provider.clone()),
        &headers,
    )
    .await;
    assert_eq!(duplicate.status, StatusCode::CONFLICT);

    let mut renamed = provider.clone();
    renamed["displayName"] = "Corp, renamed".into();
    renamed["clientAuthentication"] = json!({});
    let no_version = call(
        &app,
        Method::PUT,
        &format!("/admin/identity-providers/{id}"),
        Some(renamed.clone()),
        &headers,
    )
    .await;
    assert_eq!(no_version.status, StatusCode::PRECONDITION_REQUIRED);
    let updated = call(
        &app,
        Method::PUT,
        &format!("/admin/identity-providers/{id}"),
        Some(renamed),
        &[
            ("authorization", auth.as_str()),
            ("if-match", etag.as_str()),
        ],
    )
    .await;
    assert_eq!(updated.status, StatusCode::OK, "{}", updated.body);
    let read = call(
        &app,
        Method::GET,
        &format!("/admin/identity-providers/{id}"),
        None,
        &headers,
    )
    .await;
    assert_eq!(read.body["displayName"], "Corp, renamed");
    assert_eq!(
        read.body["clientAuthentication"]["hasSecret"], true,
        "the secret was kept"
    );

    let mut bad = provider;
    bad["scheme"] = "local".into();
    let refused = call(
        &app,
        Method::POST,
        "/admin/identity-providers",
        Some(bad),
        &headers,
    )
    .await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST);
    assert_eq!(refused.body["errors"][0]["code"], "validation_failed");

    let deleted = call(
        &app,
        Method::DELETE,
        &format!("/admin/identity-providers/{id}"),
        None,
        &headers,
    )
    .await;
    assert_eq!(deleted.status, StatusCode::NO_CONTENT);
    let gone = call(
        &app,
        Method::GET,
        &format!("/admin/identity-providers/{id}"),
        None,
        &headers,
    )
    .await;
    assert_eq!(gone.status, StatusCode::NOT_FOUND);
}
