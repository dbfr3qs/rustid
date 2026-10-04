//! The protected resource route (`[protected_resource]`), which the FAPI 2
//! conformance plan calls with the tokens it gets.

use std::path::{Path, PathBuf};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use rustid_core::clients::Clients;
use rustid_core::keys::{KeyConfig, KeyMaterial};
use rustid_core::options::ProtocolOptions;
use rustid_core::resources::Resources;
use rustid_http::{AppState, ProtocolState};
use serde_json::Value;
use tower::ServiceExt;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn state(resource: Option<&str>) -> AppState {
    let mut clients = Clients::load(&fixture("clients.json")).unwrap();
    for (id, mode) in [("dpop.iat", "Iat"), ("dpop.nonce", "Nonce")] {
        clients.clients.push(
            serde_json::from_value(serde_json::json!({
                "clientId": id,
                "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
                "allowedGrantTypes": ["client_credentials"],
                "allowedScopes": ["api1"],
                "requireDPoP": true,
                "dpopValidationMode": mode,
            }))
            .unwrap(),
        );
    }
    let key = KeyConfig {
        kid: "k1".into(),
        alg: "RS256".into(),
        key_file: fixture("signing-key.pem"),
        cert_file: None,
    };
    AppState::new(ProtocolState {
        options: ProtocolOptions {
            issuer_uri: Some("https://idsrv.test".into()),
            ..Default::default()
        },
        keys: rustid_core::key_service::KeyService::new(
            KeyMaterial::load(&[key], &[]).unwrap(),
            None,
        ),
        features: Default::default(),
        stores: rustid_store_memory::stores(
            clients,
            Resources::load(&fixture("resources.json")).unwrap(),
        ),
        events: Default::default(),
        path_base: None,
        interaction: Default::default(),
        protected_resource: resource.map(str::to_owned),
        dcr: None,
        saml: Default::default(),
    })
}

async fn send(
    state: AppState,
    request: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let response = rustid_http::router(state).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

async fn client_token(state: AppState) -> String {
    let (_, _, body) = send(
        state,
        Request::post("/connect/token")
            .header("host", "server")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(
                "grant_type=client_credentials&client_id=client&client_secret=secret&scope=api1",
            ))
            .unwrap(),
    )
    .await;
    let json: Value = serde_json::from_slice(&body).unwrap();
    json["access_token"].as_str().unwrap().to_owned()
}

fn get(path: &str, authorization: Option<&str>) -> Request<Body> {
    let mut request = Request::get(path).header("host", "server");
    if let Some(a) = authorization {
        request = request.header("authorization", a);
    }
    request.body(Body::empty()).unwrap()
}

#[tokio::test]
async fn the_resource_serves_valid_tokens_and_challenges_others() {
    let state = state(Some("/fapi2/resource"));
    let token = client_token(state.clone()).await;
    let (status, headers, body) = send(
        state.clone(),
        get("/fapi2/resource", Some(&format!("Bearer {token}"))),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["sub"], "client");

    let (status, headers, _) = send(state, get("/fapi2/resource", None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(headers["www-authenticate"], "Bearer, DPoP");
}

#[tokio::test]
async fn without_the_config_there_is_no_resource() {
    let (status, _, _) = send(state(None), get("/fapi2/resource", None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

fn proof_key() -> rustid_core::keys::LoadedKey {
    rustid_core::keys::LoadedKey::load(&KeyConfig {
        kid: "proof".into(),
        alg: "RS256".into(),
        key_file: fixture("client-jwt-key.pem"),
        cert_file: None,
    })
    .unwrap()
}

/// A DPoP proof by `key` for `method` and `url`, bound to `token` when
/// given (`ath`), with a server nonce when given.
fn proof(
    key: &rustid_core::keys::LoadedKey,
    method: &str,
    url: &str,
    token: Option<&str>,
    nonce: Option<&str>,
) -> String {
    use rustid_core::jwt::b64url;
    let public = key.public_jwk();
    let header = serde_json::json!({
        "typ": "dpop+jwt", "alg": key.alg,
        "jwk": { "kty": public.kty, "n": public.n, "e": public.e },
    });
    let mut payload = serde_json::json!({
        "jti": rustid_core::tokens::new_jwt_id(),
        "htm": method, "htu": url,
        "iat": chrono::Utc::now().timestamp(),
    });
    if let Some(token) = token {
        payload["ath"] = serde_json::json!(b64url(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes()).as_ref()
        ));
    }
    if let Some(nonce) = nonce {
        payload["nonce"] = serde_json::json!(nonce);
    }
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(payload.to_string().as_bytes())
    );
    format!("{input}.{}", b64url(&key.sign(input.as_bytes()).unwrap()))
}

/// A DPoP-bound token for `client`, answering a nonce challenge if asked.
async fn bound_token(state: AppState, client: &str, key: &rustid_core::keys::LoadedKey) -> String {
    let body =
        format!("grant_type=client_credentials&client_id={client}&client_secret=secret&scope=api1");
    let token_request = |dpop: String| {
        Request::post("/connect/token")
            .header("host", "server")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("dpop", dpop)
            .body(Body::from(body.clone()))
            .unwrap()
    };
    let url = "http://server/connect/token";
    let (status, headers, bytes) = send(
        state.clone(),
        token_request(proof(key, "POST", url, None, None)),
    )
    .await;
    let bytes = if status == StatusCode::OK {
        bytes
    } else {
        let nonce = headers["dpop-nonce"].to_str().unwrap().to_owned();
        send(
            state,
            token_request(proof(key, "POST", url, None, Some(&nonce))),
        )
        .await
        .2
    };
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    json["access_token"].as_str().unwrap().to_owned()
}

fn get_with_proof(token: &str, dpop: &str) -> Request<Body> {
    Request::get("/fapi2/resource")
        .header("host", "server")
        .header("authorization", format!("DPoP {token}"))
        .header("dpop", dpop)
        .body(Body::empty())
        .unwrap()
}

const RESOURCE_URL: &str = "http://server/fapi2/resource";

#[tokio::test]
async fn a_dpop_bound_token_is_served_with_its_proof() {
    let state = state(Some("/fapi2/resource"));
    let key = proof_key();
    let token = bound_token(state.clone(), "dpop.iat", &key).await;
    let dpop = proof(&key, "GET", RESOURCE_URL, Some(&token), None);
    let (status, _, body) = send(state.clone(), get_with_proof(&token, &dpop)).await;
    assert_eq!(status, StatusCode::OK);
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["sub"], "dpop.iat");
    // The same proof again is a replay; the challenge names the DPoP error.
    let (status, headers, _) = send(state, get_with_proof(&token, &dpop)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers["www-authenticate"].to_str().unwrap();
    assert!(
        challenge.starts_with("Bearer, DPoP error=\"invalid_dpop_proof\""),
        "{challenge}"
    );
}

#[tokio::test]
async fn a_nonce_client_is_given_a_nonce_by_the_resource() {
    let state = state(Some("/fapi2/resource"));
    let key = proof_key();
    let token = bound_token(state.clone(), "dpop.nonce", &key).await;
    let dpop = proof(&key, "GET", RESOURCE_URL, Some(&token), None);
    let (status, headers, _) = send(state.clone(), get_with_proof(&token, &dpop)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let challenge = headers["www-authenticate"].to_str().unwrap();
    assert!(
        challenge.contains("DPoP error=\"use_dpop_nonce\""),
        "{challenge}"
    );
    let nonce = headers["dpop-nonce"].to_str().unwrap().to_owned();
    let dpop = proof(&key, "GET", RESOURCE_URL, Some(&token), Some(&nonce));
    let (status, _, _) = send(state, get_with_proof(&token, &dpop)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn the_resource_echoes_or_issues_a_fapi_interaction_id() {
    // FAPI: the resource returns the client's x-fapi-interaction-id, or a
    // fresh one when the client sent none.
    let state = state(Some("/fapi2/resource"));
    let token = client_token(state.clone()).await;
    let auth = format!("Bearer {token}");
    let mut request = get("/fapi2/resource", Some(&auth));
    request.headers_mut().insert(
        "x-fapi-interaction-id",
        "c770aef3-6784-41f7-8e0e-ff5f97bddb3a".parse().unwrap(),
    );
    let (status, headers, _) = send(state.clone(), request).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["x-fapi-interaction-id"],
        "c770aef3-6784-41f7-8e0e-ff5f97bddb3a"
    );
    let (_, headers, _) = send(state, get("/fapi2/resource", Some(&auth))).await;
    let issued = headers["x-fapi-interaction-id"].to_str().unwrap();
    assert_eq!(issued.len(), 36, "a UUID: {issued}");
}
