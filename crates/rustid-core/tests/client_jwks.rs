//! Clients' keys at `jwksUri`: fetched, cached, refetched for a key they
//! rotated in (at most once a minute), and used to authenticate them.

mod support;

use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use rustid_core::clients::Client;
use rustid_core::form::Form;
use rustid_core::keys::{KeyOrigin, LoadedKey, generate_pkcs8};
use rustid_core::request_uri::{Fetched, RequestUriFetcher};
use rustid_core::token::process;
use serde_json::json;
use support::Fixture;

const JWKS_URI: &str = "https://client.example/jwks";

fn key(kid: &str) -> LoadedKey {
    let der = generate_pkcs8("RS256", 2048).unwrap();
    LoadedKey::from_der(kid, "RS256", &der, None, &KeyOrigin::default()).unwrap()
}

fn jwk(key: &LoadedKey) -> serde_json::Value {
    let public = key.public_jwk();
    json!({ "kty": public.kty, "kid": public.kid, "n": public.n, "e": public.e, "alg": "RS256", "use": "sig" })
}

/// Serves a key set at `JWKS_URI`, counting the requests.
#[derive(Default)]
struct Fake {
    keys: Mutex<Vec<serde_json::Value>>,
    body: Mutex<Option<String>>,
    gets: Mutex<usize>,
    /// The URL is unreachable.
    down: Mutex<bool>,
}

#[async_trait::async_trait]
impl RequestUriFetcher for Fake {
    async fn fetch(&self, uri: &str) -> Option<Fetched> {
        assert_eq!(uri, JWKS_URI);
        *self.gets.lock().unwrap() += 1;
        // A real fetch yields; concurrent callers must not each fetch.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        if *self.down.lock().unwrap() {
            return None;
        }
        let body = self
            .body
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| json!({ "keys": *self.keys.lock().unwrap() }).to_string());
        Some(Fetched {
            status: 200,
            content_type: Some("application/json".into()),
            body,
        })
    }
}

fn fixture(fake: Arc<Fake>, jwks_uri: Option<&str>) -> Fixture {
    let mut f = Fixture::new();
    f.stores.request_uri = fake;
    f.edit_clients(|clients| {
        clients.push(
            serde_json::from_value::<Client>(json!({
                "clientId": "remote",
                "allowedGrantTypes": ["client_credentials"],
                "allowedScopes": ["api1"],
                "jwksUri": jwks_uri,
            }))
            .unwrap(),
        );
    });
    f
}

fn assertion(key: &LoadedKey) -> String {
    let now = Utc::now().timestamp();
    let claims = json!({
        "iss": "remote", "sub": "remote", "aud": support::ISSUER,
        "exp": now + 60, "iat": now, "jti": rustid_core::grants::new_handle(),
    });
    rustid_core::jwt::encode(key, &[], claims.as_object().unwrap()).unwrap()
}

async fn authenticate(f: &Fixture, key: &LoadedKey) -> bool {
    let mut ctx = f.ctx(Utc::now());
    ctx.private_key_jwt = true;
    let form = Form::from_pairs(&[
        ("grant_type", "client_credentials"),
        ("client_id", "remote"),
        ("scope", "api1"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", &assertion(key)),
    ]);
    process(&ctx, None, &form).await.is_ok()
}

#[tokio::test]
async fn a_key_only_at_the_jwks_uri_authenticates_the_client() {
    let k1 = key("k1");
    let fake = Arc::new(Fake::default());
    fake.keys.lock().unwrap().push(jwk(&k1));
    let f = fixture(fake.clone(), Some(JWKS_URI));
    assert!(authenticate(&f, &k1).await);
    assert!(authenticate(&f, &k1).await, "again, from the cache");
    assert_eq!(*fake.gets.lock().unwrap(), 1);
    // Another key nobody published: refused.
    assert!(!authenticate(&f, &key("k9")).await);
}

#[tokio::test]
async fn a_key_rotated_in_is_fetched_once_a_minute_at_most() {
    let k1 = key("k1");
    let k2 = key("k2");
    let fake = Arc::new(Fake::default());
    fake.keys.lock().unwrap().push(jwk(&k1));
    let f = fixture(fake.clone(), Some(JWKS_URI));
    let client = f
        .clients
        .clients
        .iter()
        .find(|c| c.client_id == "remote")
        .unwrap()
        .clone();
    let now = Utc::now();
    let keys = |token: &str, at| {
        let stores = f.stores.clone();
        let client = client.clone();
        let token = token.to_owned();
        async move {
            rustid_core::client_jwks::with_jwks_uri_keys(&stores, &client, Some(&token), at)
                .await
                .client_secrets
                .len()
        }
    };
    assert_eq!(keys(&assertion(&k1), now).await, 1);
    // The client rotates k2 in; within the minute of the first fetch a
    // token naming it waits, after it refetches.
    fake.keys.lock().unwrap().push(jwk(&k2));
    assert_eq!(keys(&assertion(&k2), now + Duration::seconds(30)).await, 1);
    let t = now + Duration::seconds(60);
    assert_eq!(keys(&assertion(&k2), t).await, 2);
    assert_eq!(*fake.gets.lock().unwrap(), 2);
    // Another unknown kid within the minute: no further request.
    let k3 = key("k3");
    keys(&assertion(&k3), t + Duration::seconds(30)).await;
    keys(&assertion(&k3), t + Duration::seconds(31)).await;
    assert_eq!(*fake.gets.lock().unwrap(), 2);
    // A minute later it may ask again.
    keys(&assertion(&k3), t + Duration::seconds(61)).await;
    assert_eq!(*fake.gets.lock().unwrap(), 3);
}

#[tokio::test]
async fn the_key_set_is_kept_for_five_minutes() {
    let k1 = key("k1");
    let fake = Arc::new(Fake::default());
    fake.keys.lock().unwrap().push(jwk(&k1));
    let f = fixture(fake.clone(), Some(JWKS_URI));
    let client = f
        .clients
        .clients
        .iter()
        .find(|c| c.client_id == "remote")
        .unwrap()
        .clone();
    let now = Utc::now();
    let token = assertion(&k1);
    for at in [now, now + Duration::seconds(299)] {
        rustid_core::client_jwks::with_jwks_uri_keys(&f.stores, &client, Some(&token), at).await;
    }
    assert_eq!(*fake.gets.lock().unwrap(), 1);
    rustid_core::client_jwks::with_jwks_uri_keys(
        &f.stores,
        &client,
        Some(&token),
        now + Duration::seconds(301),
    )
    .await;
    assert_eq!(*fake.gets.lock().unwrap(), 2);
}

#[tokio::test]
async fn a_malformed_key_set_is_no_keys() {
    let fake = Arc::new(Fake::default());
    *fake.body.lock().unwrap() = Some("<html>".into());
    let f = fixture(fake.clone(), Some(JWKS_URI));
    assert!(!authenticate(&f, &key("k1")).await);
}

#[tokio::test]
async fn a_client_without_a_jwks_uri_fetches_nothing() {
    let fake = Arc::new(Fake::default());
    let f = fixture(fake.clone(), None);
    assert!(!authenticate(&f, &key("k1")).await);
    assert_eq!(*fake.gets.lock().unwrap(), 0);
}

fn request_object_fixture(fake: Arc<Fake>) -> Fixture {
    let mut f = Fixture::new();
    f.stores.request_uri = fake;
    f.edit_clients(|clients| {
        clients.push(
            serde_json::from_value::<Client>(json!({
                "clientId": "remote-jar",
                "allowedGrantTypes": ["implicit"],
                "redirectUris": ["https://client.test/callback"],
                "allowedScopes": ["openid"],
                "requireConsent": false,
                "requireClientSecret": false,
                "jwksUri": JWKS_URI,
            }))
            .unwrap(),
        );
        clients.push(
            serde_json::from_value::<Client>(json!({
                "clientId": "remote-ciba",
                "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
                "allowedGrantTypes": ["urn:openid:params:grant-type:ciba"],
                "allowedScopes": ["openid"],
                "jwksUri": JWKS_URI,
            }))
            .unwrap(),
        );
    });
    f
}

fn object(key: &LoadedKey, client_id: &str, extra: serde_json::Value) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": client_id, "aud": support::ISSUER, "exp": now + 60, "iat": now,
        "jti": rustid_core::grants::new_handle(), "client_id": client_id,
    });
    for (k, v) in extra.as_object().unwrap() {
        claims[k] = v.clone();
    }
    rustid_core::jwt::encode(key, &[], claims.as_object().unwrap()).unwrap()
}

#[tokio::test]
async fn an_authorize_request_object_signed_with_a_key_at_the_jwks_uri_validates() {
    use rustid_core::authorize::validate;
    use rustid_core::params::Params;
    let k1 = key("k1");
    let fake = Arc::new(Fake::default());
    fake.keys.lock().unwrap().push(jwk(&k1));
    let f = request_object_fixture(fake.clone());
    let run = |key: LoadedKey| {
        let f = &f;
        async move {
            let request = object(
                &key,
                "remote-jar",
                json!({
                    "response_type": "id_token", "scope": "openid", "nonce": "n",
                    "redirect_uri": "https://client.test/callback",
                }),
            );
            let raw = Params::parse_query(&format!(
                "client_id=remote-jar&response_type=id_token&request={request}"
            ));
            validate(&f.authorize_ctx(Utc::now()), raw, None)
                .await
                .is_ok()
        }
    };
    assert!(run(k1).await);
    assert!(!run(key("k9")).await, "a key nobody published");
}

#[tokio::test]
async fn a_ciba_request_object_signed_with_a_key_at_the_jwks_uri_validates() {
    use rustid_core::token::{TokenError, TokenFailure};
    let k1 = key("k1");
    let fake = Arc::new(Fake::default());
    fake.keys.lock().unwrap().push(jwk(&k1));
    let f = request_object_fixture(fake.clone());
    let run = |key: LoadedKey| {
        let f = &f;
        async move {
            let request = object(
                &key,
                "remote-ciba",
                json!({ "scope": "openid", "login_hint": "alice" }),
            );
            let form = Form::from_pairs(&[
                ("client_id", "remote-ciba"),
                ("client_secret", "secret"),
                ("request", &request),
            ]);
            match rustid_core::ciba::authorize(&f.ctx(Utc::now()), None, &form).await {
                Err(TokenFailure::Protocol(TokenError { description, .. })) => description,
                _ => None,
            }
        }
    };
    let bad_object = Some("Invalid JWT request".to_owned());
    assert_ne!(run(k1).await, bad_object);
    assert_eq!(run(key("k9")).await, bad_object, "a key nobody published");
}

fn remote(f: &Fixture) -> Client {
    f.clients
        .clients
        .iter()
        .find(|c| c.client_id == "remote")
        .unwrap()
        .clone()
}

async fn key_count(f: &Fixture, client: &Client, token: &str, at: chrono::DateTime<Utc>) -> usize {
    rustid_core::client_jwks::with_jwks_uri_keys(&f.stores, client, Some(token), at)
        .await
        .client_secrets
        .len()
}

#[tokio::test]
async fn concurrent_requests_share_one_fetch() {
    let k1 = key("k1");
    let fake = Arc::new(Fake::default());
    fake.keys.lock().unwrap().push(jwk(&k1));
    let f = fixture(fake.clone(), Some(JWKS_URI));
    let client = remote(&f);
    let now = Utc::now();
    let known = assertion(&k1);
    // A cold cache: one fetch however many ask at once.
    let counts =
        futures::future::join_all((0..20).map(|_| key_count(&f, &client, &known, now))).await;
    assert!(counts.iter().all(|n| *n == 1), "{counts:?}");
    assert_eq!(*fake.gets.lock().unwrap(), 1);
    // An unknown kid from many requests at once: one refetch.
    let unknown = assertion(&key("k9"));
    futures::future::join_all((0..20).map(|_| key_count(&f, &client, &unknown, now))).await;
    assert_eq!(
        *fake.gets.lock().unwrap(),
        1,
        "the cold fetch was this minute's"
    );
    let later = now + Duration::seconds(61);
    futures::future::join_all((0..20).map(|_| key_count(&f, &client, &unknown, later))).await;
    assert_eq!(*fake.gets.lock().unwrap(), 2);
}

#[tokio::test]
async fn a_failed_fetch_keeps_the_keys_already_fetched() {
    let k1 = key("k1");
    let fake = Arc::new(Fake::default());
    fake.keys.lock().unwrap().push(jwk(&k1));
    let f = fixture(fake.clone(), Some(JWKS_URI));
    let client = remote(&f);
    let now = Utc::now();
    let known = assertion(&k1);
    assert_eq!(key_count(&f, &client, &known, now).await, 1);
    *fake.down.lock().unwrap() = true;
    // A made-up kid forces a refetch, which fails: k1 stays.
    let unknown = assertion(&key("k9"));
    assert_eq!(
        key_count(&f, &client, &unknown, now + Duration::seconds(61)).await,
        1
    );
    assert_eq!(*fake.gets.lock().unwrap(), 2);
    // Expired, and the fetch fails: still k1, and no fetch again within the minute.
    let expired = now + Duration::seconds(400);
    assert_eq!(key_count(&f, &client, &known, expired).await, 1);
    assert_eq!(
        key_count(&f, &client, &known, expired + Duration::seconds(30)).await,
        1
    );
    assert_eq!(*fake.gets.lock().unwrap(), 3);
    // Back up: the next attempt replaces the set.
    *fake.down.lock().unwrap() = false;
    fake.keys.lock().unwrap().push(jwk(&key("k2")));
    assert_eq!(
        key_count(&f, &client, &known, expired + Duration::seconds(61)).await,
        2
    );
}

#[tokio::test]
async fn a_key_set_is_cut_to_a_hundred_keys() {
    let k1 = key("k1");
    let fake = Arc::new(Fake::default());
    let mut keys = vec![jwk(&k1)];
    keys.extend(
        (0..150).map(|i| json!({ "kty": "RSA", "kid": format!("x{i}"), "n": "sXch", "e": "AQAB" })),
    );
    *fake.keys.lock().unwrap() = keys;
    let f = fixture(fake.clone(), Some(JWKS_URI));
    let client = remote(&f);
    assert_eq!(
        key_count(&f, &client, &assertion(&k1), Utc::now()).await,
        100
    );
}

/// Serves an empty key set at any URL.
struct AnyUrl;

#[async_trait::async_trait]
impl RequestUriFetcher for AnyUrl {
    async fn fetch(&self, _: &str) -> Option<Fetched> {
        Some(Fetched {
            status: 200,
            content_type: None,
            body: r#"{"keys":[{"kty":"RSA","kid":"a","n":"sXch","e":"AQAB"}]}"#.into(),
        })
    }
}

#[tokio::test]
async fn the_cache_holds_a_bounded_number_of_urls() {
    let mut f = Fixture::new();
    f.stores.request_uri = Arc::new(AnyUrl);
    let now = Utc::now();
    let max = rustid_core::client_jwks::MAX_URLS;
    for i in 0..max + 50 {
        let client = serde_json::from_value::<Client>(json!({
            "clientId": "c", "jwksUri": format!("https://c{i}.example/jwks"),
        }))
        .unwrap();
        rustid_core::client_jwks::with_jwks_uri_keys(&f.stores, &client, None, now).await;
    }
    assert!(f.stores.client_jwks.len() <= max);
}
