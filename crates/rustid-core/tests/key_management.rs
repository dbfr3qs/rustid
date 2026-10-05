//! Key manager behaviour, through the
//! public API: a manual clock stands in for the system clock and a counting
//! in-memory store for the signing key store.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone, Utc};
use rustid_core::data_protection::DataProtector;
use rustid_core::key_management::{Clock, KeyManager};
use rustid_core::key_service::KeyService;
use rustid_core::keys::KeyMaterial;
use rustid_core::options::{KeyManagementOptions, SigningAlgorithmOptions, TimeSpan};
use rustid_core::stores::{SerializedKey, SigningKeyStore, StoreError};
use rustid_store_memory::InMemorySigningKeyStore;

const DAY: i64 = 24 * 60 * 60;

struct ManualClock(Mutex<DateTime<Utc>>);

impl ManualClock {
    fn at(t: DateTime<Utc>) -> Arc<Self> {
        Arc::new(ManualClock(Mutex::new(t)))
    }

    fn advance(&self, by: Duration) {
        *self.0.lock().unwrap() += by;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

/// Counts loads and records deletes.
#[derive(Default)]
struct Store {
    inner: InMemorySigningKeyStore,
    loads: AtomicUsize,
    deleted: Mutex<Vec<String>>,
}

#[async_trait]
impl SigningKeyStore for Store {
    async fn load_keys(&self) -> Result<Vec<SerializedKey>, StoreError> {
        self.loads.fetch_add(1, Ordering::SeqCst);
        self.inner.load_keys().await
    }
    async fn store_key(&self, key: SerializedKey) -> Result<(), StoreError> {
        self.inner.store_key(key).await
    }
    async fn delete_key(&self, id: &str) -> Result<(), StoreError> {
        self.deleted.lock().unwrap().push(id.to_owned());
        self.inner.delete_key(id).await
    }
}

impl Store {
    async fn keys(&self) -> Vec<SerializedKey> {
        self.inner.load_keys().await.unwrap()
    }
}

fn start() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

/// Defaults with no initialization delays, so tests never sleep.
fn options() -> KeyManagementOptions {
    KeyManagementOptions {
        initialization_synchronization_delay: TimeSpan(0),
        initialization_duration: TimeSpan(0),
        ..Default::default()
    }
    .validated()
    .unwrap()
}

fn ring() -> Arc<DataProtector> {
    Arc::new(DataProtector::new([("test", &[7u8; 32][..])]).unwrap())
}

fn manager(
    options: KeyManagementOptions,
    store: &Arc<Store>,
    clock: &Arc<ManualClock>,
) -> KeyManager {
    KeyManager::new(
        options,
        store.clone(),
        Some(ring()),
        clock.clone(),
        "https://idsrv.test",
    )
}

async fn current_ids(m: &KeyManager) -> Vec<String> {
    m.get_current_keys()
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .collect()
}

async fn all_ids(m: &KeyManager) -> Vec<String> {
    let mut ids: Vec<String> = m
        .get_all_keys()
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn the_first_request_creates_protects_and_persists_a_key() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let m = manager(options(), &store, &clock);
    let current = m.get_current_keys().await.unwrap();
    assert_eq!(current.len(), 1);
    let key = &current[0];
    assert_eq!(key.algorithm, "RS256");
    assert_eq!(key.created, start());
    assert!(key.id.len() == 32 && key.id.chars().all(|c| matches!(c, '0'..='9' | 'A'..='F')));
    assert_eq!(key.key.jwk.kid, key.id);
    let stored = store.keys().await;
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].id, key.id);
    assert!(stored[0].data_protected);
    assert!(
        stored[0].data.starts_with("v1.test."),
        "sealed with the ring"
    );
    assert!(!stored[0].is_x509_certificate);
    // Later requests reuse it, from the cache.
    let loads = store.loads.load(Ordering::SeqCst);
    assert_eq!(current_ids(&m).await, std::slice::from_ref(&key.id));
    assert_eq!(
        store.loads.load(Ordering::SeqCst),
        loads,
        "served from the cache"
    );
    // A new instance on the same store loads the same key.
    let other = manager(options(), &store, &clock);
    assert_eq!(current_ids(&other).await, std::slice::from_ref(&key.id));
    assert_eq!(store.keys().await.len(), 1);
}

#[tokio::test]
async fn unprotected_keys_are_stored_in_the_clear_when_protection_is_off() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let options = KeyManagementOptions {
        data_protect_keys: false,
        ..options()
    };
    let m = KeyManager::new(options.clone(), store.clone(), None, clock.clone(), "x");
    m.get_current_keys().await.unwrap();
    let stored = store.keys().await;
    assert!(!stored[0].data_protected);
    assert!(stored[0].data.contains("pkcs8"));
    // A protected key can't be read without the ring and is skipped.
    let (store2, _) = (Arc::new(Store::default()), ());
    manager(self::options(), &store2, &clock)
        .get_current_keys()
        .await
        .unwrap();
    let protected = store2.keys().await.remove(0);
    let unreadable = KeyManager::new(options, store2.clone(), None, clock.clone(), "x");
    let current = unreadable.get_current_keys().await.unwrap();
    assert_ne!(
        current[0].id, protected.id,
        "a new key replaces the unreadable one"
    );
}

#[tokio::test]
async fn keys_rotate_after_the_rotation_interval_less_propagation_time() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let m = manager(options(), &store, &clock);
    let first = current_ids(&m).await.remove(0);
    // 90-day rotation, 14-day propagation: just before day 76 no successor
    // is needed; from day 76 one is created, announced but not yet signing.
    clock.advance(Duration::days(76) - Duration::seconds(1));
    let early = manager(options(), &store, &clock);
    assert_eq!(all_ids(&early).await, std::slice::from_ref(&first));
    clock.advance(Duration::seconds(1));
    let m = manager(options(), &store, &clock);
    assert_eq!(
        current_ids(&m).await,
        std::slice::from_ref(&first),
        "the old key still signs"
    );
    let all = all_ids(&m).await;
    assert_eq!(all.len(), 2, "the successor is published for validation");
    let second = all.into_iter().find(|id| *id != first).unwrap();
    // At exactly 90 days the old key still signs (it is retired only once
    // `created + rotation_interval < now`); a second later the successor does.
    clock.advance(Duration::days(14));
    let m = manager(options(), &store, &clock);
    assert_eq!(current_ids(&m).await, std::slice::from_ref(&first));
    clock.advance(Duration::seconds(1));
    let m = manager(options(), &store, &clock);
    assert_eq!(current_ids(&m).await, std::slice::from_ref(&second));
    assert!(all_ids(&m).await.contains(&first));
    // After rotation interval plus retention the old key is deleted.
    clock.advance(Duration::days(15));
    let m = manager(options(), &store, &clock);
    m.get_current_keys().await.unwrap();
    assert_eq!(
        store.deleted.lock().unwrap().as_slice(),
        std::slice::from_ref(&first)
    );
    assert!(!all_ids(&m).await.contains(&first));
}

#[tokio::test]
async fn retired_keys_are_kept_when_deletion_is_off() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    manager(options(), &store, &clock)
        .get_current_keys()
        .await
        .unwrap();
    clock.advance(Duration::days(200));
    let keep = KeyManagementOptions {
        delete_retired_keys: false,
        ..options()
    };
    let m = manager(keep, &store, &clock);
    let current = current_ids(&m).await;
    assert_eq!(current.len(), 1);
    assert!(store.deleted.lock().unwrap().is_empty());
    assert_eq!(
        store.keys().await.len(),
        2,
        "the retired key remains stored"
    );
    assert_eq!(all_ids(&m).await, current, "but is not used or published");
}

#[tokio::test]
async fn the_oldest_active_key_signs_and_unactivated_keys_wait() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    // Two keys: one 20 days old (active), one 1 day old (announced).
    manager(options(), &store, &clock)
        .get_current_keys()
        .await
        .unwrap();
    let old = store.keys().await.remove(0).id;
    clock.advance(Duration::days(19));
    let fresh = Arc::new(Store::default());
    manager(options(), &fresh, &clock)
        .get_current_keys()
        .await
        .unwrap();
    let young = fresh.keys().await.remove(0);
    store.store_key(young.clone()).await.unwrap();
    clock.advance(Duration::days(1));
    let m = manager(options(), &store, &clock);
    assert_eq!(current_ids(&m).await, [old]);
    assert_eq!(all_ids(&m).await.len(), 2);
}

#[tokio::test]
async fn a_brand_new_deployment_signs_with_its_unpropagated_key() {
    // Only a key created within the propagation time exists: it falls back
    // to ignoring the activation delay.
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let m = manager(options(), &store, &clock);
    let id = current_ids(&m).await.remove(0);
    clock.advance(Duration::days(1));
    assert_eq!(current_ids(&manager(options(), &store, &clock)).await, [id]);
}

#[tokio::test]
async fn keys_created_in_the_future_are_usable() {
    // Clock skew between instances: a key stamped ahead of this clock.
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let ahead = ManualClock::at(start() + Duration::minutes(5));
    let id = current_ids(&manager(options(), &store, &ahead))
        .await
        .remove(0);
    assert_eq!(current_ids(&manager(options(), &store, &clock)).await, [id]);
    assert_eq!(store.keys().await.len(), 1);
}

#[tokio::test]
async fn one_key_is_kept_per_configured_algorithm() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let algs = |names: &[&str]| {
        KeyManagementOptions {
            signing_algorithms: names
                .iter()
                .map(|n| SigningAlgorithmOptions {
                    name: (*n).into(),
                    use_x509_certificate: false,
                })
                .collect(),
            ..options()
        }
        .validated()
        .unwrap()
    };
    let m = manager(algs(&["ES256", "RS256"]), &store, &clock);
    let current = m.get_current_keys().await.unwrap();
    let found: Vec<&str> = current.iter().map(|k| k.algorithm.as_str()).collect();
    assert_eq!(found, ["ES256", "RS256"]);
    // Dropping an algorithm from the configuration ignores its keys.
    let m = manager(algs(&["RS256"]), &store, &clock);
    let current = m.get_current_keys().await.unwrap();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].algorithm, "RS256");
    assert_eq!(all_ids(&m).await.len(), 1);
    // Adding one creates a key for it.
    let m = manager(algs(&["RS256", "PS256"]), &store, &clock);
    let found: Vec<String> = m
        .get_current_keys()
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.algorithm)
        .collect();
    assert_eq!(found, ["RS256", "PS256"]);
}

#[tokio::test]
async fn x509_keys_carry_a_certificate_and_plain_keys_do_not_qualify() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let plain = manager(options(), &store, &clock);
    let plain_id = current_ids(&plain).await.remove(0);
    let x509 = KeyManagementOptions {
        signing_algorithms: vec![SigningAlgorithmOptions {
            name: "RS256".into(),
            use_x509_certificate: true,
        }],
        ..options()
    };
    let m = manager(x509, &store, &clock);
    let current = m.get_current_keys().await.unwrap();
    assert_ne!(
        current[0].id, plain_id,
        "a key without a certificate can't sign"
    );
    assert!(current[0].has_x509_certificate());
    assert!(current[0].key.jwk.x5c.is_some());
    assert!(store.keys().await.iter().any(|k| k.is_x509_certificate));
}

#[tokio::test]
async fn caches_last_for_the_key_cache_duration_and_initial_keys_briefly() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let fresh = KeyManagementOptions {
        initialization_duration: TimeSpan(5 * 60),
        ..options()
    };
    let m = manager(fresh, &store, &clock);
    m.get_current_keys().await.unwrap();
    let loads = store.loads.load(Ordering::SeqCst);
    // New keys are cached for initialization_key_cache_duration (1 minute).
    clock.advance(Duration::seconds(30));
    m.get_current_keys().await.unwrap();
    assert_eq!(store.loads.load(Ordering::SeqCst), loads);
    clock.advance(Duration::seconds(31));
    m.get_current_keys().await.unwrap();
    assert_eq!(store.loads.load(Ordering::SeqCst), loads + 1);
    // Established keys are cached for key_cache_duration (24 hours).
    clock.advance(Duration::days(1));
    m.get_current_keys().await.unwrap();
    let loads = store.loads.load(Ordering::SeqCst);
    clock.advance(Duration::hours(23));
    m.get_current_keys().await.unwrap();
    assert_eq!(store.loads.load(Ordering::SeqCst), loads);
    clock.advance(Duration::hours(2));
    m.get_current_keys().await.unwrap();
    assert_eq!(store.loads.load(Ordering::SeqCst), loads + 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_first_requests_create_one_key() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let m = Arc::new(manager(options(), &store, &clock));
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let m = m.clone();
            tokio::spawn(async move { m.get_current_keys().await.unwrap().remove(0).id })
        })
        .collect();
    let mut ids = Vec::new();
    for t in tasks {
        ids.push(t.await.unwrap());
    }
    ids.dedup();
    assert_eq!(ids.len(), 1, "{ids:?}");
    assert_eq!(store.keys().await.len(), 1);
}

#[tokio::test]
async fn the_key_service_prefers_static_keys_and_publishes_automatic_ones_first() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let m = Arc::new(manager(options(), &store, &clock));
    let static_key = rustid_core::keys::KeyConfig {
        kid: "static".into(),
        alg: "ES256".into(),
        key_file: std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/signing-ec-p256.pem"),
        cert_file: None,
    };
    let material = KeyMaterial::load(&[static_key], &[]).unwrap();
    let service = KeyService::new(material, Some(m.clone()));
    let automatic = current_ids(&m).await.remove(0);
    assert_eq!(
        service.signing_key(&[]).await.unwrap().unwrap().kid,
        "static"
    );
    assert_eq!(
        service
            .signing_key(&["RS256".into()])
            .await
            .unwrap()
            .unwrap()
            .kid,
        automatic
    );
    assert!(
        service
            .signing_key(&["PS512".into()])
            .await
            .unwrap()
            .is_none()
    );
    let published: Vec<String> = service
        .validation_keys()
        .await
        .unwrap()
        .iter()
        .map(|k| k.kid.clone())
        .collect();
    assert_eq!(published, [automatic, "static".into()]);
    assert_eq!(
        service.signing_algorithms().await.unwrap(),
        ["ES256", "RS256"]
    );
    // Without static keys the automatic default-algorithm key signs.
    let only = KeyService::new(KeyMaterial::default(), Some(m));
    assert_eq!(only.signing_key(&[]).await.unwrap().unwrap().alg, "RS256");
}

#[test]
fn options_are_validated() {
    let base = || KeyManagementOptions::default();
    let names = |v: &[(&str, bool)]| {
        v.iter()
            .map(|(n, x)| SigningAlgorithmOptions {
                name: (*n).into(),
                use_x509_certificate: *x,
            })
            .collect()
    };
    let defaults = base().validated().unwrap();
    assert_eq!(defaults.signing_algorithms, names(&[("RS256", false)]));
    assert_eq!(
        defaults.key_cache_duration,
        TimeSpan(DAY),
        "within half the propagation"
    );
    for (bad, message) in [
        (
            KeyManagementOptions {
                signing_algorithms: names(&[("RS256", false), ("RS256", false)]),
                ..base()
            },
            "Duplicate",
        ),
        (
            KeyManagementOptions {
                signing_algorithms: names(&[("HS256", false)]),
                ..base()
            },
            "Invalid signing algorithm",
        ),
        (
            KeyManagementOptions {
                signing_algorithms: names(&[("ES256", true)]),
                ..base()
            },
            "EC keys",
        ),
        (
            KeyManagementOptions {
                rotation_interval: TimeSpan(14 * DAY),
                ..base()
            },
            "longer than propagation_time",
        ),
        (
            KeyManagementOptions {
                retention_duration: TimeSpan(0),
                ..base()
            },
            "retention_duration must be greater than zero",
        ),
        (
            KeyManagementOptions {
                key_cache_duration: TimeSpan(-1),
                ..base()
            },
            "key_cache_duration",
        ),
        (
            KeyManagementOptions {
                rsa_key_size: 1024,
                ..base()
            },
            "rsa_key_size",
        ),
    ] {
        let err = bad.validated().unwrap_err();
        assert!(err.contains(message), "{err}");
    }
    let capped = KeyManagementOptions {
        key_cache_duration: TimeSpan(30 * DAY),
        ..base()
    }
    .validated()
    .unwrap();
    assert_eq!(capped.key_cache_duration, TimeSpan(7 * DAY));
}

struct Down;

#[async_trait]
impl SigningKeyStore for Down {
    async fn load_keys(&self) -> Result<Vec<SerializedKey>, StoreError> {
        Err(StoreError::Backend("down".into()))
    }
    async fn store_key(&self, _: SerializedKey) -> Result<(), StoreError> {
        Err(StoreError::Backend("down".into()))
    }
    async fn delete_key(&self, _: &str) -> Result<(), StoreError> {
        Err(StoreError::Backend("down".into()))
    }
}

#[tokio::test]
async fn a_failing_store_is_an_error_not_a_panic() {
    let m = KeyManager::new(
        options(),
        Arc::new(Down),
        Some(ring()),
        ManualClock::at(start()),
        "x",
    );
    assert!(m.get_current_keys().await.is_err());
    let service = KeyService::new(KeyMaterial::default(), Some(Arc::new(m)));
    assert_eq!(
        service.validation_keys().await.unwrap_err(),
        StoreError::Backend("down".into())
    );
}

#[test]
fn durations_beyond_a_century_are_rejected_instead_of_overflowing() {
    for set in [
        (|o: &mut KeyManagementOptions| o.rotation_interval = TimeSpan(i64::MAX))
            as fn(&mut KeyManagementOptions),
        |o| o.retention_duration = TimeSpan(36_501 * DAY),
        |o| o.propagation_time = TimeSpan(i64::MAX / 2),
        |o| o.key_cache_duration = TimeSpan(i64::MAX),
        |o| o.initialization_duration = TimeSpan(i64::MAX),
        |o| o.initialization_key_cache_duration = TimeSpan(i64::MAX),
        |o| o.initialization_synchronization_delay = TimeSpan(i64::MAX),
    ] {
        let mut options = KeyManagementOptions::default();
        set(&mut options);
        let err = options.validated().unwrap_err();
        assert!(err.contains("at most 36500 days"), "{err}");
    }
}

fn fixture_key(
    kid: &str,
    alg: &str,
    key: &str,
    cert: Option<&str>,
) -> rustid_core::keys::KeyConfig {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    rustid_core::keys::KeyConfig {
        kid: kid.into(),
        alg: alg.into(),
        key_file: dir.join(key),
        cert_file: cert.map(|c| dir.join(c)),
    }
}

fn pem_der(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name);
    pem::parse(std::fs::read_to_string(path).unwrap())
        .unwrap()
        .into_contents()
}

/// Certificate keys
/// are listed, EC keys without one are skipped, validation keys never are.
#[tokio::test]
async fn saml_lists_the_signing_certificates() {
    let material = KeyMaterial::load(
        &[
            fixture_key(
                "c",
                "RS256",
                "validation-cert-key.pem",
                Some("validation-cert.pem"),
            ),
            fixture_key("e", "ES256", "signing-ec-p256.pem", None),
        ],
        &[fixture_key("v", "RS256", "validation-rsa.pem", None)],
    )
    .unwrap();
    let service = KeyService::new(material, None);
    assert_eq!(
        service
            .saml_signing_certificates("https://idp.example/Saml2")
            .await
            .unwrap(),
        [pem_der("validation-cert.pem")]
    );
}

#[tokio::test]
async fn saml_refuses_a_static_rsa_key_without_a_certificate() {
    let material =
        KeyMaterial::load(&[fixture_key("r", "RS256", "signing-key.pem", None)], &[]).unwrap();
    let error = KeyService::new(material, None)
        .saml_signing_certificates("https://idp.example/Saml2")
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "Cannot auto-wrap a manually registered RSA key as an X509 certificate for SAML signing. Use an X509 certificate directly or enable automatic key management."
    );
}

/// A managed RSA key gets a self-signed
/// certificate, CN the SAML issuer, serial from the key id, valid from the
/// key's creation for the retirement age, critical digitalSignature usage.
#[tokio::test]
async fn saml_wraps_managed_rsa_keys_in_certificates() {
    use x509_parser::prelude::*;
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let options = options();
    let retirement = options.key_retirement_age();
    let m = Arc::new(manager(options, &store, &clock));
    let service = KeyService::new(KeyMaterial::default(), Some(m.clone()));
    let current = m.get_current_keys().await.unwrap().remove(0);
    let certificates = service
        .saml_signing_certificates("https://idp.example/Saml2")
        .await
        .unwrap();
    assert_eq!(certificates.len(), 1);
    let (_, cert) = X509Certificate::from_der(&certificates[0]).unwrap();
    let cn = cert.subject().iter_common_name().next().unwrap();
    assert_eq!(cn.as_str().unwrap(), "https://idp.example/Saml2");
    assert_eq!(
        cn.attr_value().tag(),
        x509_parser::der_parser::asn1_rs::Tag::Utf8String
    );
    assert_eq!(cert.issuer(), cert.subject(), "self-signed");
    let hash = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, current.id.as_bytes());
    let mut serial = hash.as_ref()[..8].to_vec();
    serial[0] &= 0x7F;
    assert_eq!(cert.raw_serial(), serial.as_slice());
    assert_eq!(
        cert.validity().not_before.timestamp(),
        current.created.timestamp()
    );
    assert_eq!(
        cert.validity().not_after.timestamp(),
        current.created.timestamp() + retirement
    );
    let usage = cert.key_usage().unwrap().unwrap();
    assert!(usage.critical);
    assert!(usage.value.digital_signature());
    assert_eq!(usage.value.flags, 1, "digitalSignature only");
    assert!(cert.extended_key_usage().unwrap().is_none());
    assert_eq!(
        cert.signature_algorithm.algorithm,
        x509_parser::oid_registry::OID_PKCS1_SHA256WITHRSA
    );
    aws_lc_rs::signature::UnparsedPublicKey::new(
        &aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256,
        &cert.public_key().subject_public_key.data,
    )
    .verify(cert.tbs_certificate.as_ref(), &cert.signature_value.data)
    .expect("self-signed with the key");
    // The certificate holds the managed key's public key.
    use base64::Engine;
    let n = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(current.key.jwk.n.as_ref().unwrap())
        .unwrap();
    let x509_parser::public_key::PublicKey::RSA(rsa) = cert.public_key().parsed().unwrap() else {
        panic!("an RSA key")
    };
    assert_eq!(
        rsa.modulus
            .iter()
            .skip_while(|b| **b == 0)
            .copied()
            .collect::<Vec<_>>(),
        n
    );
    // Cached by key id.
    assert_eq!(
        service
            .saml_signing_certificates("https://other.example")
            .await
            .unwrap(),
        certificates
    );
}

#[tokio::test]
async fn saml_lists_managed_x509_keys_as_they_are() {
    let (store, clock) = (Arc::new(Store::default()), ManualClock::at(start()));
    let options = KeyManagementOptions {
        signing_algorithms: vec![SigningAlgorithmOptions {
            name: "RS256".into(),
            use_x509_certificate: true,
        }],
        ..options()
    };
    let m = Arc::new(manager(options, &store, &clock));
    let service = KeyService::new(KeyMaterial::default(), Some(m.clone()));
    let current = m.get_current_keys().await.unwrap().remove(0);
    use base64::Engine;
    let own = base64::engine::general_purpose::STANDARD
        .decode(&current.key.jwk.x5c.as_ref().unwrap()[0])
        .unwrap();
    assert_eq!(
        service
            .saml_signing_certificates("https://idp.example")
            .await
            .unwrap(),
        [own]
    );
}

#[tokio::test]
async fn a_sealed_key_loads_as_a_managed_key() {
    // seal_key is how `rustid-server import` stores a migrated key: the
    // key manager reads it back like one it made.
    let store = Arc::new(Store {
        inner: InMemorySigningKeyStore::default(),
        loads: AtomicUsize::new(0),
        deleted: Mutex::new(Vec::new()),
    });
    let clock = ManualClock::at(start());
    let pkcs8 = rustid_core::keys::generate_pkcs8("RS256", 2048).unwrap();
    let sealed = rustid_core::key_management::seal_key(
        "migrated-1",
        "RS256",
        start(),
        &pkcs8,
        None,
        Some(&ring()),
    )
    .unwrap();
    assert!(sealed.data_protected);
    assert!(!sealed.data.contains(&base64_pkcs8(&pkcs8)));
    store.store_key(sealed).await.unwrap();
    let m = manager(options(), &store, &clock);
    assert_eq!(current_ids(&m).await, vec!["migrated-1"]);
}

fn base64_pkcs8(pkcs8: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(pkcs8)
}
