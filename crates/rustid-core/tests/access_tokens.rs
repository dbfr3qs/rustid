mod support;

use chrono::{Duration, TimeZone, Utc};
use rustid_core::access_tokens::{EXPIRED_TOKEN, INVALID_TOKEN, ValidationContext, validate};
use rustid_core::jwt;
use serde_json::{Map, Value, json};
use support::{Fixture, ISSUER};

fn now() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_800_000_000, 0).unwrap()
}

fn vctx(f: &Fixture, at: chrono::DateTime<Utc>) -> ValidationContext<'_> {
    ValidationContext {
        options: &f.options,
        stores: &f.stores,
        keys: &f.keys,
        issuer: ISSUER,
        now: at,
    }
}

/// A token signed with `file`, header `typ` and `kid` as given.
fn jwt_with(file: &str, kid: &str, typ: Option<&str>, payload: Value) -> String {
    let key = support::key(file, kid, "RS256");
    let header: Vec<(&str, &str)> = typ.map(|t| vec![("typ", t)]).unwrap_or_default();
    let payload: Map<String, Value> = payload.as_object().unwrap().clone();
    jwt::encode(&key, &header, &payload).unwrap()
}

fn payload(overrides: Value) -> Value {
    let t = now().timestamp();
    let mut p = json!({"iss": ISSUER, "nbf": t, "iat": t, "exp": t + 60,
                       "aud": "api", "scope": ["api1"], "client_id": "client"});
    for (k, v) in overrides.as_object().unwrap() {
        if v.is_null() {
            p.as_object_mut().unwrap().remove(k);
        } else {
            p[k] = v.clone();
        }
    }
    p
}

fn good(overrides: Value) -> String {
    jwt_with(
        "signing-key.pem",
        "fixture-rsa-1",
        Some("at+jwt"),
        payload(overrides),
    )
}

#[tokio::test]
async fn issued_jwts_validate_with_their_claims() {
    let f = Fixture::new();
    let token = f.issue("client", "api1 api2", now()).await;
    let valid = validate(&vctx(&f, now()), &token).await.unwrap().unwrap();
    let types: Vec<&str> = valid.claims.iter().map(|c| c.claim_type.as_str()).collect();
    assert_eq!(
        types,
        [
            "iss",
            "nbf",
            "iat",
            "exp",
            "aud",
            "aud",
            "scope",
            "scope",
            "client_id",
            "jti"
        ]
    );
}

#[tokio::test]
async fn jwt_checks() {
    let f = Fixture::new();
    let ctx = vctx(&f, now());
    let t = now().timestamp();
    assert!(validate(&ctx, &good(json!({}))).await.unwrap().is_ok());
    let wrong_typ = jwt_with(
        "signing-key.pem",
        "fixture-rsa-1",
        Some("JWT"),
        payload(json!({})),
    );
    assert_eq!(
        validate(&ctx, &wrong_typ).await.unwrap(),
        Err(INVALID_TOKEN)
    );
    let no_typ = jwt_with("signing-key.pem", "fixture-rsa-1", None, payload(json!({})));
    assert_eq!(validate(&ctx, &no_typ).await.unwrap(), Err(INVALID_TOKEN));
    assert_eq!(
        validate(&ctx, &good(json!({"iss": "https://other"})))
            .await
            .unwrap(),
        Err(INVALID_TOKEN)
    );
    assert_eq!(
        validate(&ctx, &good(json!({"exp": null}))).await.unwrap(),
        Err(INVALID_TOKEN)
    );
    // Five minutes of clock skew either side.
    assert!(
        validate(&ctx, &good(json!({"exp": t - 299, "nbf": t - 400})))
            .await
            .unwrap()
            .is_ok()
    );
    assert_eq!(
        validate(&ctx, &good(json!({"exp": t - 301, "nbf": t - 400})))
            .await
            .unwrap(),
        Err(EXPIRED_TOKEN)
    );
    assert!(
        validate(&ctx, &good(json!({"nbf": t + 299, "exp": t + 900})))
            .await
            .unwrap()
            .is_ok()
    );
    assert_eq!(
        validate(&ctx, &good(json!({"nbf": t + 301, "exp": t + 900})))
            .await
            .unwrap(),
        Err(INVALID_TOKEN)
    );
    assert_eq!(
        validate(&ctx, &good(json!({"nbf": t + 70}))).await.unwrap(),
        Err(INVALID_TOKEN),
        "nbf after exp"
    );
    assert_eq!(
        validate(&ctx, &good(json!({"client_id": "client.disabled"})))
            .await
            .unwrap(),
        Err(INVALID_TOKEN)
    );
    assert_eq!(
        validate(&ctx, &good(json!({"client_id": "nobody"})))
            .await
            .unwrap(),
        Err(INVALID_TOKEN)
    );
    assert!(
        validate(&ctx, &good(json!({"client_id": null})))
            .await
            .unwrap()
            .is_ok()
    );
    let mut tampered = good(json!({}));
    tampered.pop();
    tampered.push('A');
    assert_eq!(validate(&ctx, &tampered).await.unwrap(), Err(INVALID_TOKEN));
    assert_eq!(validate(&ctx, "a.b.c").await.unwrap(), Err(INVALID_TOKEN));
}

#[tokio::test]
async fn signature_keys_are_chosen_by_kid() {
    let f = Fixture::new();
    let ctx = vctx(&f, now());
    let validation_only = jwt_with(
        "validation-rsa.pem",
        "fixture-validation-rsa",
        Some("at+jwt"),
        payload(json!({})),
    );
    assert!(validate(&ctx, &validation_only).await.unwrap().is_ok());
    let unknown_kid = jwt_with(
        "validation-rsa.pem",
        "unknown",
        Some("at+jwt"),
        payload(json!({})),
    );
    assert!(
        validate(&ctx, &unknown_kid).await.unwrap().is_ok(),
        "every key is tried"
    );
    let wrong_kid = jwt_with(
        "validation-rsa.pem",
        "fixture-rsa-1",
        Some("at+jwt"),
        payload(json!({})),
    );
    assert_eq!(
        validate(&ctx, &wrong_kid).await.unwrap(),
        Err(INVALID_TOKEN),
        "only the named key"
    );
    let untrusted = jwt_with(
        "client-jwt-key.pem",
        "x",
        Some("at+jwt"),
        payload(json!({})),
    );
    assert_eq!(
        validate(&ctx, &untrusted).await.unwrap(),
        Err(INVALID_TOKEN)
    );
}

#[tokio::test]
async fn space_delimited_scopes_are_split_and_moved_last() {
    let f = Fixture::new();
    let valid = validate(&vctx(&f, now()), &good(json!({"scope": "api1 api2"})))
        .await
        .unwrap()
        .unwrap();
    let last: Vec<(&str, &str)> = valid.claims[valid.claims.len() - 2..]
        .iter()
        .map(|c| (c.claim_type.as_str(), c.value.as_str()))
        .collect();
    assert_eq!(last, [("scope", "api1"), ("scope", "api2")]);
}

#[tokio::test]
async fn reference_tokens_validate_until_their_lifetime_ends() {
    let f = Fixture::new();
    let handle = f.issue("client.reference", "api1", now()).await;
    let valid = validate(&vctx(&f, now()), &handle).await.unwrap().unwrap();
    let flat: Vec<(&str, &str)> = valid
        .claims
        .iter()
        .filter(|c| c.claim_type != "jti")
        .map(|c| (c.claim_type.as_str(), c.value.as_str()))
        .collect();
    assert_eq!(
        flat,
        [
            ("iss", ISSUER),
            ("nbf", "1800000000"),
            ("iat", "1800000000"),
            ("exp", "1800003600"),
            ("aud", "api1-resource"),
            ("aud", "api"),
            ("client_id", "client.reference"),
            ("client_role", "service"),
            ("client_count", "7"),
            ("scope", "api1"),
        ]
    );
    assert!(
        validate(&vctx(&f, now() + Duration::seconds(3600)), &handle)
            .await
            .unwrap()
            .is_ok()
    );
    // No clock skew, and an expired token is removed.
    assert_eq!(
        validate(
            &vctx(&f, now() + Duration::milliseconds(3_600_001)),
            &handle
        )
        .await
        .unwrap(),
        Err(EXPIRED_TOKEN)
    );
    assert_eq!(
        validate(&vctx(&f, now()), &handle).await.unwrap(),
        Err(INVALID_TOKEN)
    );
}

#[tokio::test]
async fn reference_token_lookups_fail_closed() {
    let mut f = Fixture::new();
    let ctx = vctx(&f, now());
    assert_eq!(validate(&ctx, "nope").await.unwrap(), Err(INVALID_TOKEN));
    assert_eq!(
        validate(&ctx, &"A".repeat(101)).await.unwrap(),
        Err(INVALID_TOKEN)
    );
    let handle = f.issue("client.reference", "api1", now()).await;
    f.edit_clients(|clients| {
        clients
            .iter_mut()
            .find(|c| c.client_id == "client.reference")
            .unwrap()
            .enabled = false;
    });
    assert_eq!(
        validate(&vctx(&f, now()), &handle).await.unwrap(),
        Err(INVALID_TOKEN)
    );
}

#[tokio::test]
async fn unreadable_reference_data_is_an_invalid_token() {
    let f = Fixture::new();
    let handle = f.issue("client.reference", "api1", now()).await;
    let key = rustid_core::grants::hashed_key(&handle, "reference_token");
    let mut grant = f.stores.grants.get(&key).await.unwrap().unwrap();
    grant.data = "{not json".into();
    f.stores.grants.store(grant).await.unwrap();
    assert_eq!(
        validate(&vctx(&f, now()), &handle).await.unwrap(),
        Err(INVALID_TOKEN)
    );
}

#[tokio::test]
async fn extreme_lifetimes_do_not_overflow() {
    let f = Fixture::new();
    let ctx = vctx(&f, now());
    assert!(
        validate(&ctx, &good(json!({"exp": i64::MAX, "nbf": i64::MIN})))
            .await
            .unwrap()
            .is_ok()
    );
    assert_eq!(
        validate(&ctx, &good(json!({"exp": i64::MIN, "nbf": null})))
            .await
            .unwrap(),
        Err(EXPIRED_TOKEN)
    );
    assert_eq!(
        validate(&ctx, &good(json!({"exp": 1e300, "nbf": null})))
            .await
            .unwrap(),
        Err(INVALID_TOKEN)
    );
}

#[tokio::test]
async fn numeric_dates_must_read_as_integers_and_are_rounded() {
    let f = Fixture::new();
    let ctx = vctx(&f, now());
    let t = now().timestamp();
    for bad in [
        json!({"iat": "abc"}),
        json!({"nbf": "soon"}),
        json!({"iat": 1e300}),
        json!({"exp": true}),
    ] {
        assert_eq!(
            validate(&ctx, &good(bad.clone())).await.unwrap(),
            Err(INVALID_TOKEN),
            "{bad}"
        );
    }
    let valid = validate(
        &ctx,
        &good(json!({"iat": 12.5, "nbf": "13.5", "exp": format!("{}.9", t + 60)})),
    )
    .await
    .unwrap()
    .unwrap();
    let dates: Vec<(&str, &str, &str)> = valid.claims[1..4]
        .iter()
        .map(|c| {
            (
                c.claim_type.as_str(),
                c.value.as_str(),
                c.value_type.as_str(),
            )
        })
        .collect();
    let int64 = "http://www.w3.org/2001/XMLSchema#integer64";
    let exp = (t + 61).to_string();
    assert_eq!(
        dates,
        [
            ("nbf", "14", int64),
            ("iat", "12", int64),
            ("exp", exp.as_str(), int64)
        ]
    );
}

#[tokio::test]
async fn stored_lifetimes_beyond_the_calendar_do_not_panic() {
    let f = Fixture::new();
    let handle = f.issue("client.reference", "api1", now()).await;
    let key = rustid_core::grants::hashed_key(&handle, "reference_token");
    let mut grant = f.stores.grants.get(&key).await.unwrap().unwrap();
    let mut data: serde_json::Value = serde_json::from_str(&grant.data).unwrap();
    data["lifetime"] = json!(i64::MAX);
    grant.data = data.to_string();
    f.stores.grants.store(grant).await.unwrap();
    let valid = validate(&vctx(&f, now()), &handle).await.unwrap().unwrap();
    assert_eq!(
        valid.first("exp"),
        Some(
            chrono::DateTime::<Utc>::MAX_UTC
                .timestamp()
                .to_string()
                .as_str()
        )
    );
    let mut grant = f.stores.grants.get(&key).await.unwrap().unwrap();
    let mut data: serde_json::Value = serde_json::from_str(&grant.data).unwrap();
    data["lifetime"] = json!(i64::MIN);
    grant.data = data.to_string();
    f.stores.grants.store(grant).await.unwrap();
    assert_eq!(
        validate(&vctx(&f, now()), &handle).await.unwrap(),
        Err(EXPIRED_TOKEN)
    );
}
