//! A stored provider that can't be resolved is logged once a minute per
//! version, not on every request. Its own test binary: it installs a log
//! subscriber.

use std::io::Write;
use std::sync::{Arc, Mutex};

use rustid_core::admin::identity_providers::{IdentityProviderAdmin, IdentityProviderInput};
use rustid_core::data_protection::DataProtector;
use rustid_core::federation::Federation;
use rustid_core::federation::upstream::NoUpstream;
use rustid_store_memory::InMemoryConfiguration;
use serde_json::json;

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn count(&self, needle: &str) -> usize {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .matches(needle)
            .count()
    }
}

fn protector(keys: &[(&str, [u8; 32])]) -> Arc<DataProtector> {
    Arc::new(DataProtector::new(keys.iter().map(|(id, k)| (*id, k.as_slice()))).unwrap())
}

fn input() -> IdentityProviderInput {
    IdentityProviderInput::from_json(json!({
        "scheme": "up", "displayName": "Up", "authority": "https://up.example",
        "clientId": "rustid", "clientAuthentication": { "secret": "s3cret" },
    }))
    .unwrap()
}

#[tokio::test]
async fn an_unresolvable_provider_is_logged_once_per_version() {
    let captured = Captured::default();
    let writer = captured.clone();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .finish(),
    );
    let store = Arc::new(InMemoryConfiguration::default());
    // Sealed under a key this federation doesn't hold.
    let saved = IdentityProviderAdmin::new(protector(&[("old", [1; 32])]))
        .create(store.as_ref(), input())
        .await
        .unwrap()
        .unwrap();
    let ours = protector(&[("new", [2; 32])]);
    let fed = Federation::from_store(store.clone(), ours, Arc::new(NoUpstream), false);
    for _ in 0..5 {
        assert!(fed.find("up").await.unwrap().is_none());
    }
    assert_eq!(captured.count("identity provider left out"), 1);

    // A new version (resealed under our key) is resolved at once.
    IdentityProviderAdmin::new(protector(&[("new", [2; 32]), ("old", [1; 32])]))
        .update(store.as_ref(), &saved.id, input(), saved.version)
        .await
        .unwrap()
        .unwrap();
    assert!(fed.find("up").await.unwrap().is_some());
}
