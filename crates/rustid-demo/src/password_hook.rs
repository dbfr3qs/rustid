//! The password grant hook, as a relying party's backend might host it:
//! rustid-server calls it to check a username and password (the `password`
//! grant). It accepts only calls carrying the server's hook JWT, signed
//! with a key from the server's JWKS and addressed to this hook, and checks
//! the credentials against a users file.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use axum::Json;
use axum::http::{HeaderMap, StatusCode};
use rustid_core::jwt::{Jws, PublicJwk};
use serde_json::{Value, json};

/// The hook JWT's `typ` (`rustid-hooks`).
const HOOK_TOKEN_TYPE: &str = "hook+jwt";

/// A user in the fixture format (`fixtures/users.json`).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub subject_id: String,
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub claims: Vec<Value>,
}

pub fn load_users(path: &Path) -> anyhow::Result<Vec<User>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// The username matches without
/// regard to case; a user without a password accepts a blank one.
pub fn check<'a>(users: &'a [User], username: &str, password: &str) -> Option<&'a User> {
    let user = users
        .iter()
        .find(|u| u.username.to_lowercase() == username.to_lowercase())?;
    let blank = |p: &str| p.trim().is_empty();
    let valid = match user.password.as_deref() {
        None => blank(password),
        Some(stored) if blank(stored) => blank(password),
        Some(stored) => stored == password,
    };
    valid.then_some(user)
}

/// The CIBA user hook's answer to `request` (`{login_hint, ...}`): the
/// user the login hint names by username, without regard to case.
pub fn ciba_user_answer(users: &[User], request: &Value) -> Value {
    let hint = request["login_hint"].as_str().unwrap_or_default();
    match users
        .iter()
        .find(|u| u.username.to_lowercase() == hint.to_lowercase())
    {
        Some(user) => json!({ "version": 1, "subject": { "sub": user.subject_id } }),
        None => json!({
            "version": 1,
            "error": "unknown_user_id",
            "error_description": "No such user",
        }),
    }
}

/// The hook's answer to `request` (`{username, password, ...}`).
pub fn answer(users: &[User], request: &Value) -> Value {
    let username = request["username"].as_str().unwrap_or_default();
    let password = request["password"].as_str().unwrap_or_default();
    match check(users, username, password) {
        Some(user) => json!({
            "version": 1,
            "subject": {
                "sub": user.subject_id,
                "amr": "pwd",
                "claims": user.claims.iter().map(|c| json!({
                    "type": c["type"],
                    "value": c["value"],
                    "value_type": c.get("valueType"),
                })).collect::<Vec<_>>(),
            },
        }),
        None => json!({ "version": 1, "error": "invalid_grant" }),
    }
}

/// Checks the hook JWT in `headers`: `typ`, a signature by a key in
/// `jwks`, `aud` this hook's URL, `iss` the server's issuer, not expired.
pub fn authenticate(
    headers: &HeaderMap,
    jwks: &Value,
    hook_url: &str,
    issuer: &str,
) -> Result<(), String> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or("no bearer token")?;
    let jws = Jws::decode(token).ok_or("the bearer token is not a JWS")?;
    if jws.header_str("typ") != Some(HOOK_TOKEN_TYPE) {
        return Err("not a hook token".into());
    }
    let kid = jws.header_str("kid");
    let verified = jwks["keys"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|k| kid.is_none() || k["kid"].as_str() == kid)
        .filter_map(|k| serde_json::from_value::<PublicJwk>(k.clone()).ok())
        .any(|key| jws.verify(&key));
    if !verified {
        return Err("the signature doesn't verify with the server's keys".into());
    }
    let claims = &jws.payload;
    if claims.get("aud").and_then(Value::as_str) != Some(hook_url) {
        return Err("the token is for another hook".into());
    }
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err("the token is from another issuer".into());
    }
    let now = chrono::Utc::now().timestamp();
    match claims.get("exp").and_then(Value::as_i64) {
        Some(exp) if exp > now => Ok(()),
        _ => Err("the token has expired".into()),
    }
}

/// What the hook route needs: the users, its own URL, and a way to fetch
/// the server's issuer and keys.
pub struct PasswordHook {
    pub users: Vec<User>,
    pub url: String,
}

/// Answers a hook call (`POST /hooks/password` with [`answer`], `POST
/// /hooks/ciba/user` with [`ciba_user_answer`]); `server` fetches the
/// server's issuer and JWKS for each call.
pub async fn handle<F, Fut>(
    hook: Arc<PasswordHook>,
    server: F,
    headers: HeaderMap,
    request: Value,
    answer: fn(&[User], &Value) -> Value,
) -> Result<Json<Value>, (StatusCode, String)>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(String, Value), String>>,
{
    let (issuer, jwks) = server().await.map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    authenticate(&headers, &jwks, &hook.url, &issuer).map_err(|e| {
        tracing::warn!(error = %e, url = %hook.url, "refused a hook call");
        (StatusCode::UNAUTHORIZED, e)
    })?;
    Ok(Json(answer(&hook.users, &request)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn users() -> Vec<User> {
        serde_json::from_value(json!([
            { "subjectId": "1", "username": "alice", "password": "alice" },
            { "subjectId": "3", "username": "nopass" },
        ]))
        .unwrap()
    }

    #[test]
    fn credentials_are_checked_as_the_test_user_store_does() {
        let users = users();
        assert_eq!(check(&users, "ALICE", "alice").unwrap().subject_id, "1");
        assert!(check(&users, "alice", "Alice").is_none());
        assert!(check(&users, "alice", "").is_none());
        assert!(check(&users, "unknown", "alice").is_none());
        assert_eq!(check(&users, "nopass", " ").unwrap().subject_id, "3");
        assert!(check(&users, "nopass", "x").is_none());
    }

    #[test]
    fn the_ciba_user_hook_names_users_by_username() {
        let users = users();
        let answer = |hint: &str| ciba_user_answer(&users, &json!({ "login_hint": hint }));
        assert_eq!(answer("Alice")["subject"]["sub"], "1");
        assert_eq!(answer("nobody")["error"], "unknown_user_id");
        assert_eq!(answer("")["error"], "unknown_user_id");
    }

    #[test]
    fn a_call_without_the_servers_token_is_refused() {
        let headers = HeaderMap::new();
        assert!(authenticate(&headers, &json!({ "keys": [] }), "http://x/hook", "i").is_err());
    }
}
