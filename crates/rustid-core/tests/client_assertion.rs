mod support;

use rustid_core::client_assertion::{AssertionContext, validate};
use rustid_core::clients::Secret;
use rustid_core::jwt::encode;
use rustid_core::options::ProtocolOptions;
use rustid_core::replay::InMemoryReplayCache;
use rustid_core::secrets::{ParsedSecret, ParsedSecretKind};
use serde_json::{Map, Value, json};

const NOW: i64 = 1_800_000_000;
const ISSUER: &str = "https://idsrv.test";

fn options() -> ProtocolOptions {
    ProtocolOptions {
        supported_client_assertion_signing_algorithms: vec!["RS256".into(), "ES256".into()],
        ..Default::default()
    }
}

fn claims(edit: impl FnOnce(&mut Map<String, Value>)) -> Map<String, Value> {
    let Value::Object(mut map) =
        json!({ "iss": "c", "sub": "c", "aud": ISSUER, "jti": "j1", "exp": NOW + 60, "iat": NOW })
    else {
        unreachable!()
    };
    edit(&mut map);
    map
}

struct Setup {
    secret: Secret,
    replay: InMemoryReplayCache,
    options: ProtocolOptions,
}

impl Setup {
    fn new() -> Self {
        let key = support::key("client-jwt-key.pem", "ck", "RS256");
        Setup {
            secret: Secret {
                value: support::public_jwk_json(&key),
                secret_type: "JWK".into(),
                ..Default::default()
            },
            replay: InMemoryReplayCache::default(),
            options: options(),
        }
    }

    fn check_with(&self, file: &str, alg: &str, typ: &str, payload: &Map<String, Value>) -> bool {
        let key = support::key(file, "ck", alg);
        let token = encode(&key, &[("typ", typ)], payload).unwrap();
        let parsed = ParsedSecret {
            id: "c".into(),
            credential: Some(token),
            kind: ParsedSecretKind::JwtBearer,
        };
        let ctx = AssertionContext {
            options: &self.options,
            issuer: ISSUER,
            base_url: "http://host:1/base",
            replay: &self.replay,
            now: NOW,
        };
        futures::executor::block_on(validate(&[&self.secret], &parsed, &ctx))
            .expect("the in-memory replay cache")
    }

    fn check(&self, typ: &str, payload: &Map<String, Value>) -> bool {
        self.check_with("client-jwt-key.pem", "RS256", typ, payload)
    }
}

#[test]
fn valid_assertion_is_accepted_once() {
    let s = Setup::new();
    assert!(s.check("JWT", &claims(|_| {})));
    assert!(!s.check("JWT", &claims(|_| {})), "same jti is a replay");
}

#[test]
fn legacy_audiences_include_token_endpoint_issuer_and_trailing_slash_variants() {
    let s = Setup::new();
    for (i, aud) in [
        "http://host:1/base/connect/token",
        "https://idsrv.test/connect/token",
        "https://idsrv.test/",
        "http://host:1/base/connect/par",
        "http://host:1/base/connect/ciba",
    ]
    .iter()
    .enumerate()
    {
        assert!(
            s.check(
                "JWT",
                &claims(|c| {
                    c.insert("aud".into(), json!(aud));
                    c.insert("jti".into(), json!(format!("a{i}")));
                })
            ),
            "{aud}"
        );
    }
    assert!(s.check(
        "JWT",
        &claims(|c| {
            c.insert("aud".into(), json!(["https://other.test", ISSUER]));
        })
    ));
    assert!(!s.check(
        "JWT",
        &claims(|c| {
            c.insert("aud".into(), json!("https://other.test"));
            c.insert("jti".into(), json!("b"));
        })
    ));
}

#[test]
fn strict_mode_by_typ_or_option_needs_the_issuer_as_sole_audience() {
    let s = Setup::new();
    let typ = "client-authentication+jwt";
    assert!(s.check(
        typ,
        &claims(|c| {
            c.insert("jti".into(), json!("s1"));
        })
    ));
    assert!(s.check(
        typ,
        &claims(|c| {
            c.insert("aud".into(), json!([ISSUER]));
            c.insert("jti".into(), json!("s2"));
        })
    ));
    assert!(!s.check(
        typ,
        &claims(|c| {
            c.insert("aud".into(), json!([ISSUER, "x"]));
            c.insert("jti".into(), json!("s3"));
        })
    ));
    assert!(!s.check(
        typ,
        &claims(|c| {
            c.insert("aud".into(), json!(format!("{ISSUER}/connect/token")));
            c.insert("jti".into(), json!("s4"));
        })
    ));
    let strict = Setup {
        options: ProtocolOptions {
            strict_client_assertion_audience_validation: true,
            ..options()
        },
        ..Setup::new()
    };
    assert!(
        !strict.check("JWT", &claims(|_| {})),
        "strict mode also requires the typ"
    );
}

#[test]
fn lifetime_uses_clock_skew() {
    let s = Setup::new();
    assert!(s.check(
        "JWT",
        &claims(|c| {
            c.insert("exp".into(), json!(NOW - 299));
            c.insert("jti".into(), json!("l1"));
        })
    ));
    assert!(!s.check(
        "JWT",
        &claims(|c| {
            c.insert("exp".into(), json!(NOW - 301));
            c.insert("jti".into(), json!("l2"));
        })
    ));
    assert!(!s.check(
        "JWT",
        &claims(|c| {
            c.insert("nbf".into(), json!(NOW + 301));
            c.insert("jti".into(), json!("l3"));
        })
    ));
    assert!(!s.check(
        "JWT",
        &claims(|c| {
            c.remove("exp");
        })
    ));
}

#[test]
fn identity_claims_and_jti_are_required() {
    let s = Setup::new();
    assert!(!s.check(
        "JWT",
        &claims(|c| {
            c.insert("sub".into(), json!("other"));
        })
    ));
    assert!(!s.check(
        "JWT",
        &claims(|c| {
            c.insert("iss".into(), json!("other"));
            c.insert("sub".into(), json!("other"));
        })
    ));
    assert!(!s.check(
        "JWT",
        &claims(|c| {
            c.remove("jti");
        })
    ));
}

#[test]
fn algorithm_must_be_allowed_and_key_registered() {
    let s = Setup::new();
    assert!(
        !s.check_with("client-jwt-key.pem", "PS256", "JWT", &claims(|_| {})),
        "PS256 not allowed"
    );
    assert!(
        !s.check_with("validation-rsa.pem", "RS256", "JWT", &claims(|_| {})),
        "unregistered key"
    );
    let no_jwk = Setup {
        secret: Secret {
            value: "x".into(),
            ..Default::default()
        },
        ..Setup::new()
    };
    assert!(!no_jwk.check("JWT", &claims(|_| {})));
}

#[test]
fn absurd_expiry_is_rejected_without_overflowing() {
    let s = Setup::new();
    assert!(!s.check(
        "JWT",
        &claims(|c| {
            c.insert("exp".into(), json!(i64::MAX));
        })
    ));
    assert!(!s.check(
        "JWT",
        &claims(|c| {
            c.insert("exp".into(), json!(253_402_300_800_i64));
            c.insert("jti".into(), json!("y10k"));
        })
    ));
}

#[test]
fn fractional_and_string_expiry_are_accepted() {
    let s = Setup::new();
    assert!(s.check(
        "JWT",
        &claims(|c| {
            c.insert("exp".into(), json!(NOW as f64 + 60.5));
            c.insert("jti".into(), json!("f1"));
        })
    ));
    assert!(s.check(
        "JWT",
        &claims(|c| {
            c.insert("exp".into(), json!((NOW + 60).to_string()));
            c.insert("jti".into(), json!("f2"));
        })
    ));
}

#[test]
fn unreadable_numeric_dates_reject_the_assertion() {
    let s = Setup::new();
    for (i, (name, value)) in [
        ("iat", json!("abc")),
        ("nbf", json!(null)),
        ("exp", json!(1e300)),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            !s.check(
                "JWT",
                &claims(|c| {
                    c.insert(name.into(), value.clone());
                    c.insert("jti".into(), json!(format!("u{i}")));
                })
            ),
            "{name}"
        );
    }
}
