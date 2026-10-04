//! A hook receiver for tests: answers the profile claims and subject
//! active hooks from a JSON file (a scripted profile service), and the
//! password and extension grant hooks as scripted test validators.
//!
//!   Rustid-hook-receiver <listen address> <answers file>
//!
//! The answers file is `{"claims": [{"type", "value"}...], "active": true,
//! "custom_response": {...}, "users_file": "..."}`; `users_file` (relative
//! to the answers file) holds the users `/password` checks, as
//! the test user resource owner password validator does.
//! `ciba_users_file` holds the users the CIBA user hook resolves login hints
//! to, and `inactive_subjects` the subjects `/ciba/active` reports inactive.
//! The CIBA hooks are scripted, and `GET /ciba/last` returns what the last
//! CIBA request showed them.
//! The receiver doesn't check the request's JWT: the hooks crate's own tests
//! do.

#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::Path as UrlPath;
use axum::http::StatusCode;
use axum::routing::{get, post};
use serde_json::{Map, Value, json};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let (Some(listen), Some(answers_file)) = (args.next(), args.next()) else {
        anyhow::bail!("usage: rustid-hook-receiver <listen address> <answers file>");
    };
    let answers: Value = serde_json::from_str(&std::fs::read_to_string(&answers_file)?)?;
    let claims = answers["claims"].clone();
    let active = answers["active"].as_bool().unwrap_or(true);
    let custom_response = answers["custom_response"].clone();
    let dir = Path::new(&answers_file).parent().unwrap_or(Path::new("."));
    let read_users = |field: &str| -> anyhow::Result<Arc<Vec<Value>>> {
        Ok(Arc::new(match answers[field].as_str() {
            Some(file) => serde_json::from_str(&std::fs::read_to_string(dir.join(file))?)?,
            None => Vec::new(),
        }))
    };
    let users = read_users("users_file")?;
    let ciba_users = read_users("ciba_users_file")?;
    let inactive: Arc<Vec<String>> = Arc::new(
        answers["inactive_subjects"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s.as_str().map(str::to_owned))
            .collect(),
    );
    let last: Last = Arc::default();
    let (last_user, last_request, last_notify, last_get) =
        (last.clone(), last.clone(), last.clone(), last);
    let app = axum::Router::new()
        .route("/health", get(|| async { Json(json!({ "status": "ok" })) }))
        .route(
            "/profile",
            post(move || {
                let claims = claims.clone();
                async move { Json(json!({ "version": 1, "claims": claims })) }
            }),
        )
        .route(
            "/active",
            post(move || async move { Json(json!({ "version": 1, "active": active })) }),
        )
        .route(
            "/token",
            post(move || {
                let custom_response = custom_response.clone();
                async move { Json(json!({ "version": 1, "custom_response": custom_response })) }
            }),
        )
        .route(
            "/password",
            post(move |Json(request): Json<Value>| {
                let users = users.clone();
                async move { Json(test_users(&users, &request)) }
            }),
        )
        .route(
            "/password-custom",
            post(|Json(request): Json<Value>| async move {
                Json(custom_response_password(&request))
            }),
        )
        .route(
            "/grant/{grant_type}",
            post(
                |UrlPath(grant_type): UrlPath<String>, Json(request): Json<Value>| async move {
                    extension_grant(&grant_type, &request)
                        .map(Json)
                        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
                },
            ),
        )
        .route(
            "/grant-custom",
            post(|Json(request): Json<Value>| async move {
                Json(custom_response_grant(&request))
            }),
        )
        .route(
            "/ciba/active",
            post(move |Json(request): Json<Value>| {
                let inactive = inactive.clone();
                async move {
                    let sub = request["subject"]["sub"].as_str().unwrap_or_default();
                    let active = !inactive.iter().any(|s| s == sub);
                    Json(json!({ "version": 1, "active": active }))
                }
            }),
        )
        .route(
            "/ciba/user",
            post(move |Json(request): Json<Value>| {
                let users = ciba_users.clone();
                let last = last_user.clone();
                async move {
                    *last.lock().unwrap() = json!({ "user": seen_user(&request) });
                    Json(ciba_user(&users, &request))
                }
            }),
        )
        .route(
            "/ciba/request",
            post(move |Json(request): Json<Value>| {
                let last = last_request.clone();
                async move {
                    last.lock().unwrap()["request"] = json!({
                        "client_id": request["client_id"],
                        "subject_id": request["subject_id"],
                        "binding_message": request["binding_message"],
                        "custom": request["parameters"]["custom"],
                    });
                    Json(ciba_request(&request))
                }
            }),
        )
        .route(
            "/ciba/notify",
            post(move |Json(request): Json<Value>| {
                let last = last_notify.clone();
                async move {
                    last.lock().unwrap()["notification"] = seen_notification(&request);
                    Json(json!({ "version": 1 }))
                }
            }),
        )
        .route(
            "/ciba/last",
            get(move || {
                let last = last_get.clone();
                async move { Json(last.lock().unwrap().clone()) }
            }),
        );
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn subject(sub: &str, amr: &str, claims: Value) -> Value {
    json!({ "version": 1, "subject": { "sub": sub, "amr": amr, "claims": claims } })
}

fn error(description: Option<&str>, custom: Option<Value>) -> Value {
    let mut answer = json!({ "version": 1, "error": "invalid_grant" });
    if let Some(description) = description {
        answer["error_description"] = description.into();
    }
    if let Some(custom) = custom {
        answer["custom_response"] = custom;
    }
    answer
}

fn parameter<'a>(request: &'a Value, name: &str) -> Option<&'a str> {
    request["parameters"][name].as_str()
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|v| v.trim().is_empty())
}

/// The test user resource owner password validator over the test user store: the
/// username matches case-insensitively; a user without a password accepts
/// a blank one. A failure leaves the default result, `invalid_grant`.
fn test_users(users: &[Value], request: &Value) -> Value {
    let username = request["username"].as_str().unwrap_or_default();
    let password = request["password"].as_str();
    let user = users.iter().find(|u| {
        u["username"]
            .as_str()
            .is_some_and(|n| n.to_lowercase() == username.to_lowercase())
    });
    let Some(user) = user else {
        return error(None, None);
    };
    let stored = user["password"].as_str();
    let valid = (is_blank(stored) && is_blank(password)) || stored == password;
    if !valid {
        return error(None, None);
    }
    let claims: Vec<Value> = user["claims"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| {
            let mut claim = json!({ "type": c["type"], "value": c["value"] });
            if let Some(value_type) = c["valueType"].as_str() {
                claim["value_type"] = value_type.into();
            }
            claim
        })
        .collect();
    subject(
        user["subjectId"].as_str().unwrap_or_default(),
        "pwd",
        claims.into(),
    )
}

/// `CustomResponseDto.Create` and the custom response the custom-response
/// validators answer with; the null `nested` is left out.
fn custom_response() -> Value {
    json!({
        "string_value": "some_string",
        "int_value": 42,
        "dto": {
            "string_value": "dto_string",
            "int_value": 43,
            "nested": { "string_value": "dto_nested_string", "int_value": 44 },
        },
    })
}

fn with_custom(mut answer: Value) -> Value {
    answer["custom_response"] = custom_response();
    answer
}

/// `CustomResponseResourceOwnerValidator`: valid when the username is the
/// password.
fn custom_response_password(request: &Value) -> Value {
    let username = request["username"].as_str().unwrap_or_default();
    if request["password"].as_str() == Some(username) {
        with_custom(subject(username, "password", json!([])))
    } else {
        error(Some("invalid_credential"), Some(custom_response()))
    }
}

/// `CustomResponseExtensionGrantValidator`: valid when `outcome` is
/// `succeed`.
fn custom_response_grant(request: &Value) -> Value {
    if parameter(request, "outcome") == Some("succeed") {
        with_custom(subject("bob", "custom", json!([])))
    } else {
        error(Some("invalid_credential"), Some(custom_response()))
    }
}

/// The extension grant validator, `ExtensionGrantValidator2`,
/// `NoSubjectExtensionGrantValidator` and
/// `DynamicParameterExtensionGrantValidator`. `None` when the validator
/// would throw.
fn extension_grant(grant_type: &str, request: &Value) -> Option<Value> {
    let credential = parameter(request, "custom_credential").is_some();
    Some(match grant_type {
        "custom" if credential => {
            let claims = match parameter(request, "extra_claim") {
                Some(extra) => json!([{ "type": "extra_claim", "value": extra }]),
                None => json!([]),
            };
            subject("818727", "custom", claims)
        }
        "custom" => error(Some("invalid_custom_credential"), None),
        "custom2" if credential => subject("818727", "custom", json!([])),
        "custom.nosubject" if credential => json!({ "version": 1 }),
        "custom2" | "custom.nosubject" => error(Some("invalid custom credential"), None),
        "dynamic" => return dynamic(request),
        _ => json!({ "version": 1, "error": "unsupported_grant_type" }),
    })
}

fn dynamic(request: &Value) -> Option<Value> {
    let present = |name| parameter(request, name).filter(|v| !v.is_empty());
    let mut answer = match present("sub") {
        Some(sub) => subject(sub, "delegation", json!([])),
        None => json!({ "version": 1 }),
    };
    let mut changes = Map::new();
    if let Some(client) = present("impersonated_client") {
        changes.insert("client_id".into(), client.into());
    }
    if let Some(lifetime) = present("lifetime") {
        // Int.Parse: a bad lifetime throws, which fails the request.
        let lifetime = lifetime.parse::<i32>().ok()?;
        changes.insert("access_token_lifetime".into(), lifetime.into());
    }
    if let Some(token_type @ ("jwt" | "reference")) = present("type") {
        changes.insert("access_token_type".into(), token_type.into());
    }
    if let Some(claim) = present("claim") {
        changes.insert(
            "client_claims".into(),
            json!([{ "type": "extra", "value": claim }]),
        );
    }
    answer.as_object_mut()?.extend(changes);
    Some(answer)
}

/// What the last CIBA request showed the hooks: `user`, `request` and
/// `notification`.
type Last = Arc<Mutex<Value>>;

/// A text value, with empty as absent.
fn text(value: &Value) -> Value {
    match value.as_str() {
        Some(s) if !s.is_empty() => s.into(),
        _ => Value::Null,
    }
}

fn sorted(value: &Value) -> Value {
    let mut items: Vec<String> = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    items.sort();
    items.into()
}

/// What the user hook was asked (`BackchannelAuthenticationUserValidatorContext`).
fn seen_user(request: &Value) -> Value {
    json!({
        "client_id": request["client_id"],
        "login_hint": text(&request["login_hint"]),
        "login_hint_token": text(&request["login_hint_token"]),
        "id_token_hint_sub": text(&request["id_token_hint_claims"]["sub"]),
        "user_code": text(&request["user_code"]),
        "binding_message": text(&request["binding_message"]),
    })
}

/// The login request the notification hook got (`BackchannelUserLoginRequest`).
fn seen_notification(request: &Value) -> Value {
    json!({
        "internal_id": request["internal_id"],
        "subject_id": request["subject_id"],
        "client_id": request["client_id"],
        "scopes": sorted(&request["scopes"]),
        "resource_indicators": sorted(&request["resource_indicators"]),
        "binding_message": text(&request["binding_message"]),
        "acr_values": sorted(&request["acr_values"]),
        "tenant": text(&request["tenant"]),
        "idp": text(&request["idp"]),
        "properties": request["properties"],
    })
}

/// The scripted user validator: an `id_token_hint`'s subject; otherwise
/// the login hint (or login hint token) names a user by username, or
/// `error:<code>` answers that error, or `nosub` a subject without `sub`.
fn ciba_user(users: &[Value], request: &Value) -> Value {
    if let Some(sub) = request["id_token_hint_claims"]["sub"].as_str() {
        return json!({ "version": 1, "subject": { "sub": sub } });
    }
    let hint = request["login_hint"]
        .as_str()
        .or(request["login_hint_token"].as_str())
        .unwrap_or_default();
    if let Some(error) = hint.strip_prefix("error:") {
        return json!({ "version": 1, "error": error });
    }
    if hint == "nosub" {
        return json!({ "version": 1, "subject": { "claims": [] } });
    }
    let user = users.iter().find(|u| {
        u["username"]
            .as_str()
            .is_some_and(|n| n.eq_ignore_ascii_case(hint))
    });
    match user.and_then(|u| u["subjectId"].as_str()) {
        Some(sub) => json!({ "version": 1, "subject": { "sub": sub } }),
        None => json!({ "version": 1, "error": "unknown_user_id" }),
    }
}

/// The scripted custom validator, as `CibaTestsBase`'s: a `custom`
/// parameter becomes a property, a `complex` one a nested property, and a
/// `custom_error` one refuses the request.
fn ciba_request(request: &Value) -> Value {
    let parameters = &request["parameters"];
    let mut properties = Map::new();
    if let Some(custom) = parameters["custom"].as_str() {
        properties.insert("custom".into(), custom.into());
    }
    if let Some(nested) = parameters["complex"].as_str() {
        properties.insert("complex".into(), json!({ "nested": nested }));
    }
    let mut answer = json!({ "version": 1, "properties": properties });
    if let Some(error) = parameters["custom_error"].as_str() {
        answer["error"] = error.into();
    }
    answer
}
