//! Clients' keys published at their `jwksUri`: fetched with the request URI
//! fetcher, kept for five minutes per URL on this instance, and fetched
//! again when a JWT names a key that isn't among them (a client rotating
//! keys). A URL is fetched at most once a minute, one fetch at a time;
//! requests that arrive meanwhile wait for it. A failed or malformed fetch
//! keeps the keys fetched before, if any.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::clients::{Client, SECRET_TYPE_JWK, Secret};
use crate::stores::Stores;

/// How long a fetched key set is kept.
pub const CACHE_SECONDS: i64 = 300;
/// The least time between fetches of a URL.
pub const REFETCH_SECONDS: i64 = 60;
/// The most URLs whose key sets are kept.
pub const MAX_URLS: usize = 10_000;
/// The most keys kept from one set.
pub const MAX_KEYS: usize = 100;

#[derive(Debug, Clone)]
struct Entry {
    /// Each key as JSON.
    keys: Vec<String>,
    /// When the keys were fetched; none when no fetch has succeeded.
    fetched_at: Option<i64>,
    /// When a fetch was last tried.
    tried_at: i64,
}

/// A URL's key set, locked while it's fetched.
type Slot = Arc<tokio::sync::Mutex<Option<Entry>>>;

/// The key sets fetched so far, by URL.
#[derive(Debug, Default)]
pub struct JwksCache {
    entries: Mutex<HashMap<String, Slot>>,
}

impl JwksCache {
    /// How many URLs' key sets are kept.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether no key sets are kept.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Slot>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The URL's slot. When the cache is full, idle sets that have expired
    /// go first, then any idle set.
    fn slot(&self, uri: &str, now: i64) -> Slot {
        let mut entries = self.lock();
        if let Some(slot) = entries.get(uri) {
            return slot.clone();
        }
        // A slot a request holds is in use; any other is idle.
        let idle = |slot: &Slot| Arc::strong_count(slot) == 1;
        if entries.len() >= MAX_URLS {
            entries.retain(|_, slot| {
                !idle(slot)
                    || slot.try_lock().is_ok_and(|entry| {
                        entry
                            .as_ref()
                            .is_some_and(|e| now - e.tried_at < CACHE_SECONDS)
                    })
            });
        }
        if entries.len() >= MAX_URLS {
            entries.retain(|_, slot| !idle(slot));
        }
        entries.entry(uri.to_owned()).or_default().clone()
    }
}

fn kid_of(key: &str) -> Option<String> {
    serde_json::from_str::<Value>(key)
        .ok()?
        .get("kid")?
        .as_str()
        .map(str::to_owned)
}

/// The keys of a JSON Web Key Set document, each as JSON, at most
/// [`MAX_KEYS`]; none when it isn't one.
fn parse_key_set(body: &str) -> Option<Vec<String>> {
    let document = serde_json::from_str::<Value>(body).ok()?;
    let keys = document.get("keys")?.as_array()?;
    Some(
        keys.iter()
            .filter(|k| k.is_object())
            .take(MAX_KEYS)
            .map(Value::to_string)
            .collect(),
    )
}

async fn fetch(stores: &Stores, client: &Client, uri: &str) -> Option<Vec<String>> {
    match stores.request_uri.fetch(uri).await {
        Some(fetched) if fetched.status == 200 => {
            let keys = parse_key_set(&fetched.body);
            if keys.is_none() {
                tracing::warn!(client = %client.client_id, %uri, "the client's jwks_uri isn't a JSON Web Key Set");
            }
            keys
        }
        Some(fetched) => {
            tracing::warn!(client = %client.client_id, %uri, status = fetched.status, "the client's jwks_uri couldn't be read");
            None
        }
        None => {
            tracing::warn!(client = %client.client_id, %uri, "the client's jwks_uri couldn't be reached");
            None
        }
    }
}

/// The client with the keys at its `jwksUri` added as `JWK` secrets (its
/// registered ones are kept); unchanged without one. `token` is the JWT
/// about to be verified: a `kid` it names that isn't among the keys
/// fetches the set again, at most once a minute per URL.
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
    let slot = stores.client_jwks.slot(uri, now);
    let mut guard = slot.lock().await;
    let due = match guard.as_ref() {
        None => true,
        Some(entry) => {
            let known = |kid: &str| {
                entry.keys.iter().any(|k| kid_of(k).as_deref() == Some(kid))
                    || client.client_secrets.iter().any(|s| {
                        s.secret_type == SECRET_TYPE_JWK && kid_of(&s.value).as_deref() == Some(kid)
                    })
            };
            let expired = entry.fetched_at.is_none_or(|at| now - at >= CACHE_SECONDS);
            now - entry.tried_at >= REFETCH_SECONDS
                && (expired || kid.as_deref().is_some_and(|kid| !known(kid)))
        }
    };
    if due {
        let fetched = fetch(stores, client, uri).await;
        let previous = guard.take();
        *guard = Some(match fetched {
            Some(keys) => Entry {
                keys,
                fetched_at: Some(now),
                tried_at: now,
            },
            None => Entry {
                tried_at: now,
                ..previous.unwrap_or(Entry {
                    keys: Vec::new(),
                    fetched_at: None,
                    tried_at: now,
                })
            },
        });
    }
    let keys = guard.as_ref().map(|e| e.keys.clone()).unwrap_or_default();
    drop(guard);
    let mut with = client.clone();
    with.client_secrets
        .extend(keys.into_iter().map(|value| Secret {
            value,
            secret_type: SECRET_TYPE_JWK.to_owned(),
            ..Default::default()
        }));
    Cow::Owned(with)
}
