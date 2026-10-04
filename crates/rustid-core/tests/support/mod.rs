#![allow(dead_code)]

use std::path::{Path, PathBuf};

use rustid_core::keys::{KeyConfig, LoadedKey};

pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

pub fn key(file: &str, kid: &str, alg: &str) -> LoadedKey {
    LoadedKey::load(&KeyConfig {
        kid: kid.into(),
        alg: alg.into(),
        key_file: fixture(file),
        cert_file: None,
    })
    .unwrap()
}

/// The public JWK of a loaded key, as a client would register it.
pub fn public_jwk_json(key: &LoadedKey) -> String {
    serde_json::to_string(&key.jwk).unwrap()
}

/// The shared fixtures loaded the way the default profile loads them, plus
/// a validation-only key, over in-memory stores with fresh grants.
pub struct Fixture {
    pub options: rustid_core::options::ProtocolOptions,
    pub clients: rustid_core::clients::Clients,
    pub resources: rustid_core::resources::Resources,
    /// The static keys, and the key service over them.
    pub material: rustid_core::keys::KeyMaterial,
    pub keys: rustid_core::key_service::KeyService,
    pub replay: rustid_core::replay::InMemoryReplayCache,
    pub stores: rustid_core::stores::Stores,
    /// Every event raised, whatever its type (all types enabled).
    pub events: std::sync::Arc<RecordingSink>,
    pub event_service: rustid_core::events::EventService,
    pub request: rustid_core::events::RequestInfo,
    pub protector: rustid_core::data_protection::DataProtector,
}

pub const ISSUER: &str = "https://idsrv.test";

impl Fixture {
    pub fn new() -> Self {
        let config = |file: &str, kid: &str| KeyConfig {
            kid: kid.into(),
            alg: "RS256".into(),
            key_file: fixture(file),
            cert_file: None,
        };
        let events = std::sync::Arc::new(RecordingSink::default());
        let clients = rustid_core::clients::Clients::load(&fixture("clients.json")).unwrap();
        let material = rustid_core::keys::KeyMaterial::load(
            &[config("signing-key.pem", "fixture-rsa-1")],
            &[config("validation-rsa.pem", "fixture-validation-rsa")],
        )
        .unwrap();
        let resources =
            rustid_core::resources::Resources::load(&fixture("resources.json")).unwrap();
        Fixture {
            options: rustid_core::options::ProtocolOptions {
                issuer_uri: Some(ISSUER.into()),
                ..Default::default()
            },
            stores: rustid_store_memory::stores(clients.clone(), resources.clone()),
            clients,
            resources,
            material: material.clone(),
            keys: rustid_core::key_service::KeyService::new(material, None),
            replay: Default::default(),
            events: events.clone(),
            event_service: rustid_core::events::EventService::new(
                rustid_core::options::EventsOptions {
                    raise_success_events: true,
                    raise_failure_events: true,
                    raise_information_events: true,
                    raise_error_events: true,
                },
                events,
            ),
            request: rustid_core::events::RequestInfo {
                activity_id: None,
                local_ip_address: Some("127.0.0.1:443".into()),
                remote_ip_address: Some("10.0.0.7:50000".into()),
            },
            protector: rustid_core::data_protection::DataProtector::new([(
                "test",
                [9u8; 32].as_slice(),
            )])
            .unwrap(),
        }
    }

    /// Replaces the client store with one over `edit`ed clients, keeping the
    /// grants.
    pub fn edit_clients(&mut self, edit: impl FnOnce(&mut Vec<rustid_core::clients::Client>)) {
        edit(&mut self.clients.clients);
        self.stores.clients = std::sync::Arc::new(rustid_store_memory::InMemoryClientStore::new(
            self.clients.clone(),
        ));
    }

    pub fn ctx(&self, now: chrono::DateTime<chrono::Utc>) -> rustid_core::token::TokenContext<'_> {
        rustid_core::token::TokenContext {
            options: &self.options,
            stores: &self.stores,
            keys: &self.keys,
            replay: &self.replay,
            events: &self.event_service,
            request: &self.request,
            private_key_jwt: false,
            extension_grants: &[],
            issuer: ISSUER,
            base_url: "http://h",
            dpop_proofs: &[],
            client_certificate: None,
            protector: &self.protector,
            now,
        }
    }

    pub fn authorize_ctx(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> rustid_core::authorize::AuthorizeContext<'_> {
        rustid_core::authorize::AuthorizeContext {
            options: &self.options,
            issuer: ISSUER,
            stores: &self.stores,
            events: &self.event_service,
            request: &self.request,
            now,
        }
    }

    /// What access token validation, introspection and userinfo read.
    pub fn validation_ctx(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> rustid_core::access_tokens::ValidationContext<'_> {
        rustid_core::access_tokens::ValidationContext {
            options: &self.options,
            stores: &self.stores,
            keys: &self.keys,
            issuer: ISSUER,
            now,
        }
    }

    /// A JWT access token for the `web` client and the session's subject.
    #[allow(dead_code)]
    pub async fn issue_user_token(
        &self,
        session: &rustid_core::session::UserSession,
        scope: &str,
    ) -> String {
        let client = self
            .clients
            .clients
            .iter()
            .find(|c| c.client_id == "web")
            .unwrap()
            .clone();
        let requested: Vec<String> = scope.split(' ').map(str::to_owned).collect();
        let resources = rustid_core::scopes::validate_requested_resources(
            &client,
            &self.resources.enabled(),
            &requested,
            &[],
        )
        .unwrap();
        rustid_core::issuance::Issuer {
            options: &self.options,
            stores: &self.stores,
            keys: &self.keys,
            issuer: ISSUER,
            now: chrono::Utc::now(),
        }
        .user_access_token(&client, &resources, session, Some("SID"), None)
        .await
        .unwrap()
    }

    /// Issues a client credentials token and returns the access token.
    pub async fn issue(
        &self,
        client_id: &str,
        scope: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> String {
        let form = rustid_core::form::Form::from_pairs(&[
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", "secret"),
            ("scope", scope),
        ]);
        rustid_core::token::process(&self.ctx(now), None, &form)
            .await
            .unwrap()
            .access_token
    }

    /// The stored grant for a reference token handle.
    pub async fn grant(&self, handle: &str) -> Option<rustid_core::grants::PersistedGrant> {
        let key = rustid_core::grants::hashed_key(handle, "reference_token");
        self.stores.grants.get(&key).await.unwrap()
    }
}

/// Keeps every event it is given.
#[derive(Default)]
pub struct RecordingSink(std::sync::Mutex<Vec<rustid_core::events::Event>>);

impl RecordingSink {
    /// The events so far, emptying the record.
    pub fn take(&self) -> Vec<rustid_core::events::Event> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }

    /// The names of the events so far, emptying the record.
    pub fn names(&self) -> Vec<&'static str> {
        self.take().into_iter().map(|e| e.name).collect()
    }
}

impl rustid_core::events::EventSink for RecordingSink {
    fn persist(&self, event: &rustid_core::events::Event) {
        self.0.lock().unwrap().push(event.clone());
    }
}

/// The public JWK of `key` as a DPoP proof header carries it.
pub fn dpop_jwk(key: &LoadedKey) -> serde_json::Value {
    let public: serde_json::Value = serde_json::from_str(&public_jwk_json(key)).unwrap();
    let mut jwk = serde_json::Map::new();
    for member in ["kty", "n", "e", "crv", "x", "y"] {
        if let Some(v) = public.get(member).filter(|v| !v.is_null()) {
            jwk.insert(member.into(), v.clone());
        }
    }
    serde_json::Value::Object(jwk)
}

/// RFC 7638 thumbprint of `key`.
pub fn dpop_thumbprint(key: &LoadedKey) -> String {
    let jwk = dpop_jwk(key);
    let canonical = match jwk["kty"].as_str().unwrap() {
        "RSA" => serde_json::json!({ "e": jwk["e"], "kty": "RSA", "n": jwk["n"] }),
        _ => serde_json::json!({ "crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"] }),
    };
    rustid_core::jwt::b64url(
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.to_string().as_bytes())
            .as_ref(),
    )
}

/// A fresh DPoP proof by `key` for a POST to `url`, optionally with a nonce.
pub fn dpop_proof(key: &LoadedKey, url: &str, nonce: Option<&str>) -> String {
    use rustid_core::jwt::b64url;
    let header = serde_json::json!({ "typ": "dpop+jwt", "alg": key.alg, "jwk": dpop_jwk(key) });
    let mut payload = serde_json::json!({
        "jti": rustid_core::tokens::new_jwt_id(),
        "htm": "POST",
        "htu": url,
        "iat": chrono::Utc::now().timestamp(),
    });
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

/// A fresh DPoP proof by `key` for `method` and `url`, bound to
/// `access_token` (`ath`) when given: what a protected resource receives.
#[allow(dead_code)]
pub fn dpop_resource_proof(
    key: &LoadedKey,
    method: &str,
    url: &str,
    access_token: Option<&str>,
) -> String {
    use rustid_core::jwt::b64url;
    let header = serde_json::json!({ "typ": "dpop+jwt", "alg": key.alg, "jwk": dpop_jwk(key) });
    let mut payload = serde_json::json!({
        "jti": rustid_core::tokens::new_jwt_id(),
        "htm": method,
        "htu": url,
        "iat": chrono::Utc::now().timestamp(),
    });
    if let Some(token) = access_token {
        payload["ath"] = serde_json::json!(b64url(
            aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, token.as_bytes()).as_ref()
        ));
    }
    let input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(payload.to_string().as_bytes())
    );
    format!("{input}.{}", b64url(&key.sign(input.as_bytes()).unwrap()))
}
