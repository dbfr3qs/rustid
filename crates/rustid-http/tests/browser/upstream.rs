//! A fake upstream OpenID Connect provider for the federation tests: its
//! discovery document, key set and token endpoint, answering through the
//! `UpstreamClient` trait, with knobs to make it misbehave.

use std::sync::{Arc, Mutex};

use rustid_core::clients::{Client, Clients};
use rustid_core::events::{Event, EventService, EventSink};
use rustid_core::federation::Federation;
use rustid_core::federation::provider::{Credential, IdentityProvider, Provider, Providers};
use rustid_core::federation::upstream::{FormPost, UpstreamClient, UpstreamError};
use rustid_core::keys::{KeyOrigin, LoadedKey, generate_pkcs8};
use rustid_core::options::{EventsOptions, ProtocolOptions};
use rustid_core::resources::Resources;
use rustid_http::AppState;
use serde_json::{Value, json};

use super::{fixture, protocol_state_with};

pub const AUTHORITY: &str = "https://up.example";

pub struct FakeState {
    pub discovery: Value,
    pub token_status: u16,
    /// The id token's payload, before `nonce` is added.
    pub claims: Value,
    pub nonce: String,
    /// Replaces the whole token response when set.
    pub token_body: Option<Value>,
    pub posts: Vec<FormPost>,
    pub gets: Vec<String>,
}

pub struct FakeUpstream {
    pub key: LoadedKey,
    pub state: Mutex<FakeState>,
}

impl FakeUpstream {
    pub fn new() -> Arc<FakeUpstream> {
        let der = generate_pkcs8("RS256", 2048).unwrap();
        let key = LoadedKey::from_der("up1", "RS256", &der, None, &KeyOrigin::default()).unwrap();
        Arc::new(FakeUpstream {
            key,
            state: Mutex::new(FakeState {
                discovery: json!({
                    "issuer": AUTHORITY,
                    "authorization_endpoint": "https://up.example/authorize",
                    "token_endpoint": "https://up.example/token",
                    "jwks_uri": "https://up.example/jwks",
                    "end_session_endpoint": "https://up.example/endsession",
                }),
                token_status: 200,
                claims: json!({ "sub": "upstream-user", "name": "Ada", "email": "ada@example.com" }),
                nonce: String::new(),
                token_body: None,
                posts: Vec::new(),
                gets: Vec::new(),
            }),
        })
    }

    /// The id token the next code redemption answers, for `nonce`.
    pub fn expect_nonce(&self, nonce: &str) {
        self.state.lock().unwrap().nonce = nonce.to_owned();
    }

    pub fn edit(&self, f: impl FnOnce(&mut FakeState)) {
        f(&mut self.state.lock().unwrap());
    }

    fn id_token(&self) -> String {
        let s = self.state.lock().unwrap();
        let now = chrono::Utc::now().timestamp();
        let mut payload = json!({ "iss": AUTHORITY, "aud": "rustid", "exp": now + 300,
                                  "iat": now, "nonce": s.nonce });
        for (k, v) in s.claims.as_object().unwrap() {
            payload[k] = v.clone();
        }
        rustid_core::jwt::encode(&self.key, &[], payload.as_object().unwrap()).unwrap()
    }
}

#[async_trait::async_trait]
impl UpstreamClient for FakeUpstream {
    async fn get_json(&self, url: &str) -> Result<Value, UpstreamError> {
        let mut s = self.state.lock().unwrap();
        s.gets.push(url.to_owned());
        match url {
            u if u.ends_with("/.well-known/openid-configuration") => Ok(s.discovery.clone()),
            "https://up.example/jwks" => {
                Ok(json!({ "keys": [serde_json::to_value(&self.key.jwk).unwrap()] }))
            }
            _ => Err(UpstreamError(format!("unexpected GET {url}"))),
        }
    }

    async fn post_form(&self, post: &FormPost) -> Result<(u16, Value), UpstreamError> {
        let token = self.id_token();
        let mut s = self.state.lock().unwrap();
        s.posts.push(post.clone());
        let body = s.token_body.clone().unwrap_or_else(
            || json!({ "id_token": token, "access_token": "a", "token_type": "Bearer" }),
        );
        Ok((s.token_status, body))
    }

    async fn get_userinfo(&self, _: &str, _: &str) -> Result<Value, UpstreamError> {
        Err(UpstreamError("the fake has no userinfo endpoint".into()))
    }
}

/// Records every event raised.
#[derive(Default)]
pub struct Recording(pub Mutex<Vec<Event>>);

impl EventSink for Recording {
    fn persist(&self, event: &Event) {
        self.0.lock().unwrap().push(event.clone());
    }
}

impl Recording {
    pub fn named(&self, name: &str) -> Vec<Value> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.name == name)
            .map(|e| serde_json::to_value(e).unwrap())
            .collect()
    }
}

pub fn provider_config(scheme: &str) -> IdentityProvider {
    serde_json::from_value(json!({
        "scheme": scheme, "displayName": "Upstream", "authority": AUTHORITY,
        "clientId": "rustid", "clientAuthentication": { "secret": "secret" },
    }))
    .unwrap()
}

/// `web` from the fixtures under another id, edited.
fn web_as(client_id: &str, edit: impl FnOnce(&mut Client)) -> Client {
    let clients = Clients::load(&fixture("clients.json")).unwrap();
    let mut web = clients
        .clients
        .into_iter()
        .find(|c| c.client_id == "web")
        .unwrap();
    web.client_id = client_id.to_owned();
    edit(&mut web);
    web
}

pub struct Federated {
    pub app: AppState,
    pub fake: Arc<FakeUpstream>,
    pub events: Arc<Recording>,
}

/// The fixture state plus federation: provider `up` (and a disabled `off`)
/// backed by the fake, and clients `fed.client` (any provider), `fed.only`
/// (only `up`, no local login), `fed.other` (only `other`) and
/// `fed.missing` (only an unknown scheme, no local login).
pub fn federated_with(options: ProtocolOptions) -> Federated {
    federated_custom(options, |_| {}, false)
}

/// As [`federated_with`], with provider `up` edited, and server-side
/// sessions when `sessions` is set.
pub fn federated_custom(
    options: ProtocolOptions,
    edit: impl FnOnce(&mut IdentityProvider),
    sessions: bool,
) -> Federated {
    federated_with_stores(options, edit, sessions, |_| {})
}

/// As [`federated_custom`], with the stores edited last (to wrap one).
pub fn federated_with_stores(
    options: ProtocolOptions,
    edit: impl FnOnce(&mut IdentityProvider),
    sessions: bool,
    stores: impl FnOnce(&mut rustid_core::stores::Stores),
) -> Federated {
    let fake = FakeUpstream::new();
    let events = Arc::new(Recording::default());
    let mut off = provider_config("off");
    off.enabled = false;
    let mut up = provider_config("up");
    edit(&mut up);
    let providers = Providers::new(vec![
        Provider {
            config: up,
            credential: Credential::Basic("secret".into()),
        },
        Provider {
            config: off,
            credential: Credential::Basic("secret".into()),
        },
    ])
    .unwrap();
    let mut clients = Clients::load(&fixture("clients.json")).unwrap();
    clients.clients.extend([
        web_as("fed.client", |_| {}),
        web_as("fed.only", |c| {
            c.enable_local_login = false;
            c.identity_provider_restrictions = vec!["up".into()];
        }),
        web_as("fed.other", |c| {
            c.identity_provider_restrictions = vec!["other".into()]
        }),
        web_as("fed.missing", |c| {
            c.enable_local_login = false;
            c.identity_provider_restrictions = vec!["missing".into()];
        }),
    ]);
    let mut state = protocol_state_with(options);
    state.stores = rustid_store_memory::stores(
        clients,
        Resources::load(&fixture("resources.json")).unwrap(),
    );
    state.stores.federation = Arc::new(Federation::new(providers, fake.clone(), false));
    if sessions {
        let store = Arc::new(rustid_store_memory::InMemoryServerSideSessionStore::default());
        state.stores.sessions = Some(Arc::new(
            rustid_core::server_side_sessions::ServerSideSessions {
                store: store.clone(),
                outbox: store.outbox(),
                protector: state.interaction.protector.clone(),
            },
        ));
    }
    stores(&mut state.stores);
    state.events = EventService::new(
        EventsOptions {
            raise_success_events: true,
            raise_failure_events: true,
            raise_information_events: true,
            raise_error_events: true,
        },
        events.clone(),
    );
    Federated {
        app: AppState::new(state),
        fake,
        events,
    }
}

/// As [`federated`], but federation reads its providers from the
/// configuration store, which starts with none: the admin service adds
/// them. Returns the store and the protector the admin service needs.
pub fn federated_from_store() -> (
    Federated,
    Arc<dyn rustid_core::stores::ConfigurationStore>,
    Arc<rustid_core::data_protection::DataProtector>,
) {
    let f = federated();
    let mut state = (*f.app.0).clone();
    let configuration = state.stores.configuration.clone();
    let protector = state.interaction.protector.clone();
    state.stores.federation = Arc::new(Federation::from_store(
        configuration.clone(),
        protector.clone(),
        f.fake.clone(),
        false,
    ));
    (
        Federated {
            app: AppState::new(state),
            fake: f.fake,
            events: f.events,
        },
        configuration,
        protector,
    )
}

pub fn federated() -> Federated {
    federated_with(Default::default())
}

/// A query parameter of a URL.
pub fn query(url: &str, name: &str) -> Option<String> {
    let url = url::Url::parse(&if url.starts_with('/') {
        format!("http://server{url}")
    } else {
        url.to_owned()
    })
    .unwrap();
    url.query_pairs()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

/// A grant store that fails on demand: `store` of one grant type, and
/// `remove` while `fail_remove` is set.
pub struct FlakyGrants {
    pub inner: Arc<dyn rustid_core::stores::PersistedGrantStore>,
    pub fail_store_type: Mutex<Option<String>>,
    pub fail_remove: std::sync::atomic::AtomicBool,
}

impl FlakyGrants {
    pub fn wrap(inner: Arc<dyn rustid_core::stores::PersistedGrantStore>) -> Arc<FlakyGrants> {
        Arc::new(FlakyGrants {
            inner,
            fail_store_type: Mutex::new(None),
            fail_remove: Default::default(),
        })
    }
}

fn down() -> rustid_core::stores::StoreError {
    rustid_core::stores::StoreError::Backend("down".into())
}

#[async_trait::async_trait]
impl rustid_core::stores::PersistedGrantStore for FlakyGrants {
    async fn store(
        &self,
        grant: rustid_core::grants::PersistedGrant,
    ) -> Result<(), rustid_core::stores::StoreError> {
        if self.fail_store_type.lock().unwrap().as_deref() == Some(grant.grant_type.as_str()) {
            return Err(down());
        }
        self.inner.store(grant).await
    }
    async fn get(
        &self,
        key: &str,
    ) -> Result<Option<rustid_core::grants::PersistedGrant>, rustid_core::stores::StoreError> {
        self.inner.get(key).await
    }
    async fn get_all(
        &self,
        filter: &rustid_core::grants::GrantFilter,
    ) -> Result<Vec<rustid_core::grants::PersistedGrant>, rustid_core::stores::StoreError> {
        self.inner.get_all(filter).await
    }
    async fn remove(&self, key: &str) -> Result<(), rustid_core::stores::StoreError> {
        if self.fail_remove.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(down());
        }
        self.inner.remove(key).await
    }
    async fn take(
        &self,
        key: &str,
    ) -> Result<Option<rustid_core::grants::PersistedGrant>, rustid_core::stores::StoreError> {
        self.inner.take(key).await
    }
    async fn remove_all(
        &self,
        filter: &rustid_core::grants::GrantFilter,
    ) -> Result<(), rustid_core::stores::StoreError> {
        self.inner.remove_all(filter).await
    }
    async fn remove_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        batch: usize,
        consumed_before: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<u64, rustid_core::stores::StoreError> {
        self.inner.remove_expired(now, batch, consumed_before).await
    }
}
