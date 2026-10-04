mod support;

use rustid_core::jwt::{InvalidNumericDate, Jws, PublicJwk, encode};
use serde_json::{Map, Value, json};

fn payload() -> Map<String, Value> {
    let Value::Object(map) = json!({ "sub": "x", "n": 1 }) else {
        unreachable!()
    };
    map
}

#[test]
fn encoded_tokens_decode_and_verify_for_every_family() {
    for (file, alg) in [
        ("signing-key.pem", "RS256"),
        ("signing-key.pem", "PS256"),
        ("signing-key.pem", "RS512"),
        ("signing-ec-p256.pem", "ES256"),
        ("signing-ec-p384.pem", "ES384"),
        ("signing-ec-p521.pem", "ES512"),
    ] {
        let key = support::key(file, "k1", alg);
        let token = encode(&key, &[("typ", "at+jwt")], &payload()).unwrap();
        let jws = Jws::decode(&token).unwrap();
        assert_eq!(
            Value::Object(jws.header.clone()),
            json!({ "alg": alg, "kid": "k1", "typ": "at+jwt" })
        );
        assert_eq!(jws.payload, payload());
        let public = PublicJwk::parse(&support::public_jwk_json(&key)).unwrap();
        assert!(jws.verify(&public), "{alg}");
    }
}

#[test]
fn tampering_or_the_wrong_key_fails_verification() {
    let key = support::key("signing-key.pem", "k1", "RS256");
    let other = support::key("validation-rsa.pem", "k2", "RS256");
    let token = encode(&key, &[], &payload()).unwrap();
    let public = PublicJwk::parse(&support::public_jwk_json(&key)).unwrap();
    let mut jws = Jws::decode(&token).unwrap();
    assert!(!jws.verify(&PublicJwk::parse(&support::public_jwk_json(&other)).unwrap()));
    jws.signing_input.push('x');
    assert!(!jws.verify(&public));
}

#[test]
fn algorithm_must_fit_the_key_type() {
    let key = support::key("signing-ec-p256.pem", "k1", "ES256");
    let token = encode(&key, &[], &payload()).unwrap();
    let mut jws = Jws::decode(&token).unwrap();
    jws.header.insert("alg".into(), json!("RS256"));
    assert!(!jws.verify(&PublicJwk::parse(&support::public_jwk_json(&key)).unwrap()));
}

#[test]
fn decode_requires_three_segments_and_json_objects() {
    assert!(Jws::decode("a.b").is_none());
    assert!(Jws::decode("a.b.c.d").is_none());
    assert!(Jws::decode("not.a.jwt").is_none());
    assert!(
        Jws::decode("e30.W10.c2ln").is_none(),
        "payload must be an object"
    );
    assert!(Jws::decode("e30.e30.c2ln").is_some());
}

#[test]
fn numeric_dates_accept_integers_fractions_and_numeric_strings() {
    let token = format!(
        "e30.{}.c2ln",
        rustid_core::jwt::b64url(
            br#"{"a":1790000000,"b":1790000000.9,"c":"1790000001","d":"soon","e":true,
                 "f":2.5,"g":"-1.5","h":1e300,"i":18446744073709551615,"j":null,"k":1e18}"#
        )
    );
    let jws = Jws::decode(&token).unwrap();
    assert_eq!(jws.numeric_date("a"), Ok(Some(1_790_000_000)));
    assert_eq!(
        jws.numeric_date("b"),
        Ok(Some(1_790_000_001)),
        "fractions round"
    );
    assert_eq!(jws.numeric_date("c"), Ok(Some(1_790_000_001)));
    assert_eq!(jws.numeric_date("f"), Ok(Some(2)), "half to even");
    assert_eq!(jws.numeric_date("g"), Ok(Some(-2)));
    assert_eq!(jws.numeric_date("k"), Ok(Some(1_000_000_000_000_000_000)));
    for unreadable in ["d", "e", "h", "i", "j"] {
        assert_eq!(
            jws.numeric_date(unreadable),
            Err(InvalidNumericDate),
            "{unreadable}"
        );
        assert_eq!(jws.claim_i64(unreadable), None);
    }
    assert_eq!(jws.numeric_date("absent"), Ok(None));
}
