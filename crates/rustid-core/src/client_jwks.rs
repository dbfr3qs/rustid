//! Clients' keys published at their `jwksUri`: fetched with the request URI
//! fetcher, kept for five minutes per URL on this instance, and fetched
//! again when a JWT names a key that isn't among them (a client rotating
//! keys), at most once a minute per URL. A failed or malformed fetch is no
//! keys.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::clients::{Client, SECRET_TYPE_JWK, Secret};
use crate::stores::Stores;

/// How long a fetched key set is kept.
pub const CACHE_SECONDS: i64 = 300;
/// The least time between fetches for an unknown key.
pub const REFETCH_SECONDS: i64 = 60;

#[derive(Debug, Clone)]
struct Entry {
    fetched_at: i64,
    /// Each key as JSON.
    keys: Vec<String>,
    /// When a fetch for an unknown key last happened.
    refetched_at: Option<i64>,
}

/// The key sets fetched so far, by URL.
#[derive(Debug, Default)]
pub struct JwksCache {
    entries: Mutex<HashMap<String, Entry>>,
}

impl JwksCache {
    fn get(&self, uri: &str) -> Option<Entry> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(uri)
            .cloned()
    }

    fn put(&self, uri: &str, entry: Entry) {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(uri.to_owned(), entry);
    }
}

fn kid_of(key: &str) -> Option<String> {
    serde_json::from_str::<Value>(key)
        .ok()?
        .get("kid")?
        .as_str()
        .map(str::to_owned)
}

/// The keys of a JSON Web Key Set document, each as JSON; none when it
/// isn't one.
fn parse_key_set(body: &str) -> Vec<String> {
    let Ok(document) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    document
        .get("keys")
        .and_then(Value::as_array)
        .map(|keys| {
            keys.iter()
                .filter(|k| k.is_object())
                .map(Value::to_string)
                .collect()
        })
        .unwrap_or_default()
}

async fn fetch(stores: &Stores, client: &Client, uri: &str) -> Vec<String> {
    match stores.request_uri.fetch(uri).await {
        Some(fetched) if fetched.status == 200 => {
            let keys = parse_key_set(&fetched.body);
            if keys.is_empty() {
                tracing::warn!(client = %client.client_id, %uri, "the client's jwks_uri has no keys, or isn't a JSON Web Key Set");
            }
            keys
        }
        Some(fetched) => {
            tracing::warn!(client = %client.client_id, %uri, status = fetched.status, "the client's jwks_uri couldn't be read");
            Vec::new()
        }
        None => {
            tracing::warn!(client = %client.client_id, %uri, "the client's jwks_uri couldn't be reached");
            Vec::new()
        }
    }
}

/// The client with the keys at its `jwksUri` added as `JWK` secrets (its
/// registered ones are kept); unchanged without one. `token` is the JWT
/// about to be verified: a `kid` it names that isn't among the keys
/// fetches the set again, at most once a minute.
pub async fn with_jwks_uri_keys<'c>(
    stores: &Stores,
    client: &'c Client,
    token: Option<&str>,
    now: DateTime<Utc>,
) -> Cow<'c, Client> {
    let Some(uri) = client.jwks_uri.as_deref() else {
        return Cow::Borrowed(client);
    };
    let now = now.timestamp();
    let kid = token
        .and_then(crate::jwt::Jws::decode)
        .and_then(|jws| jws.header_str("kid").map(str::to_owned));
    let cache = &stores.client_jwks;
    let entry = match cache.get(uri) {
        Some(entry) if now - entry.fetched_at < CACHE_SECONDS => {
            let known = |kid: &str| {
                entry.keys.iter().any(|k| kid_of(k).as_deref() == Some(kid))
                    || client.client_secrets.iter().any(|s| {
                        s.secret_type == SECRET_TYPE_JWK && kid_of(&s.value).as_deref() == Some(kid)
                    })
            };
            let may_refetch = entry
                .refetched_at
                .is_none_or(|at| now - at >= REFETCH_SECONDS);
            match kid.as_deref() {
                Some(kid) if !known(kid) && may_refetch => {
                    let entry = Entry {
                        fetched_at: now,
                        keys: fetch(stores, client, uri).await,
                        refetched_at: Some(now),
                    };
                    cache.put(uri, entry.clone());
                    entry
                }
                _ => entry,
            }
        }
        _ => {
            let entry = Entry {
                fetched_at: now,
                keys: fetch(stores, client, uri).await,
                refetched_at: None,
            };
            cache.put(uri, entry.clone());
            entry
        }
    };
    let mut with = client.clone();
    with.client_secrets
        .extend(entry.keys.into_iter().map(|value| Secret {
            value,
            secret_type: SECRET_TYPE_JWK.to_owned(),
            ..Default::default()
        }));
    Cow::Owned(with)
}
