use std::path::{Path, PathBuf};

use rustid_core::keys::{KeyConfig, KeyError, KeyMaterial, LoadedKey};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

fn key(kid: &str, alg: &str, file: &str) -> KeyConfig {
    KeyConfig {
        kid: kid.into(),
        alg: alg.into(),
        key_file: fixture(file),
        cert_file: None,
    }
}

#[test]
fn rsa_key_matches_the_recorded_reference_jwks() {
    let loaded = LoadedKey::load(&key("fixture-rsa-1", "RS256", "signing-key.pem")).unwrap();
    let jwks: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/expected/discovery-jwks.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let expected = &jwks["keys"][0];
    assert_eq!(serde_json::to_value(&loaded.jwk).unwrap(), *expected);
}

#[test]
fn ec_keys_render_curve_and_fixed_length_coordinates() {
    for (file, alg, crv, coord_len) in [
        ("signing-ec-p256.pem", "ES256", "P-256", 32),
        ("signing-ec-p384.pem", "ES384", "P-384", 48),
        ("signing-ec-p521.pem", "ES512", "P-521", 66),
    ] {
        let jwk = LoadedKey::load(&key("ec", alg, file)).unwrap().jwk;
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some(crv));
        let x = base64_len(jwk.x.as_deref().unwrap());
        let y = base64_len(jwk.y.as_deref().unwrap());
        assert_eq!((x, y), (coord_len, coord_len), "{file}");
        assert!(jwk.n.is_none() && jwk.e.is_none() && jwk.x5c.is_none());
    }
}

fn base64_len(s: &str) -> usize {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
        .len()
}

#[test]
fn certificate_adds_x5t_and_x5c() {
    let mut config = key("cert", "RS256", "validation-cert-key.pem");
    config.cert_file = Some(fixture("validation-cert.pem"));
    let jwk = LoadedKey::load(&config).unwrap().jwk;
    let x5t = jwk.x5t.unwrap();
    assert!(
        !x5t.contains(['+', '/', '=']),
        "x5t must be base64url: {x5t}"
    );
    let x5c = jwk.x5c.unwrap();
    assert_eq!(x5c.len(), 1);
    assert!(x5c[0].starts_with("MII"), "x5c must be standard base64 DER");
}

#[test]
fn key_type_that_does_not_fit_the_algorithm_names_kid_and_file() {
    let err = LoadedKey::load(&key("mismatch", "ES256", "signing-key.pem")).unwrap_err();
    assert!(matches!(err, KeyError::WrongKeyType { .. }));
    let msg = err.to_string();
    assert!(
        msg.contains("mismatch") && msg.contains("signing-key.pem"),
        "{msg}"
    );
}

#[test]
fn missing_key_file_names_kid_and_file() {
    let err = LoadedKey::load(&key("gone", "RS256", "no-such-key.pem")).unwrap_err();
    assert!(matches!(err, KeyError::Read { .. }));
    let msg = err.to_string();
    assert!(
        msg.contains("gone") && msg.contains("no-such-key.pem"),
        "{msg}"
    );
}

#[test]
fn unsupported_algorithm_is_rejected() {
    let err = LoadedKey::load(&key("hmac", "HS256", "signing-key.pem")).unwrap_err();
    assert!(
        matches!(err, KeyError::UnsupportedAlgorithm { .. }),
        "{err}"
    );
}

#[test]
fn duplicate_kid_across_signing_and_validation_keys_is_rejected() {
    let err = KeyMaterial::load(
        &[key("same", "RS256", "signing-key.pem")],
        &[key("same", "RS256", "validation-rsa.pem")],
    )
    .unwrap_err();
    assert!(matches!(err, KeyError::DuplicateKid { .. }), "{err}");
}

#[test]
fn signing_algorithms_are_distinct_in_order_and_validation_keys_follow_signing_keys() {
    let keys = KeyMaterial::load(
        &[
            key("a", "RS256", "signing-key.pem"),
            key("b", "ES256", "signing-ec-p256.pem"),
            key("c", "RS256", "validation-rsa.pem"),
        ],
        &[key("v", "RS256", "validation-cert-key.pem")],
    )
    .unwrap();
    assert_eq!(keys.signing_algorithms(), ["RS256", "ES256"]);
    let kids: Vec<&str> = keys.validation_keys().map(|k| k.kid.as_str()).collect();
    assert_eq!(kids, ["a", "b", "c", "v"]);
}

#[test]
fn certificate_for_a_different_key_is_rejected_naming_kid_and_certificate() {
    for (key_file, alg) in [
        ("signing-key.pem", "RS256"),
        ("signing-ec-p256.pem", "ES256"),
    ] {
        let mut config = key("mismatched", alg, key_file);
        config.cert_file = Some(fixture("validation-cert.pem"));
        let err = LoadedKey::load(&config).unwrap_err();
        assert!(
            matches!(err, KeyError::CertificateMismatch { .. }),
            "{key_file}: {err}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("mismatched") && msg.contains("validation-cert.pem"),
            "{msg}"
        );
    }
}

#[test]
fn generated_keys_load_sign_and_verify() {
    use rustid_core::keys::{KeyOrigin, LoadedKey, generate_pkcs8};
    for (alg, crv) in [
        ("RS256", None),
        ("PS384", None),
        ("ES256", Some("P-256")),
        ("ES384", Some("P-384")),
        ("ES512", Some("P-521")),
    ] {
        let pkcs8 = generate_pkcs8(alg, 2048).unwrap();
        let key = LoadedKey::from_der("k", alg, &pkcs8, None, &KeyOrigin::default()).unwrap();
        assert_eq!(key.jwk.crv.as_deref(), crv, "{alg}");
        let jws = rustid_core::jwt::encode(&key, &[], &serde_json::Map::new()).unwrap();
        assert!(
            rustid_core::jwt::Jws::decode(&jws)
                .unwrap()
                .verify(&key.public_jwk()),
            "{alg}"
        );
    }
    let big = generate_pkcs8("RS256", 3072).unwrap();
    let key = LoadedKey::from_der("k", "RS256", &big, None, &KeyOrigin::default()).unwrap();
    assert_eq!(
        key.jwk.n.as_ref().unwrap().len(),
        512,
        "3072-bit modulus in base64url"
    );
    assert!(generate_pkcs8("RS256", 1024).is_err());
    assert!(generate_pkcs8("HS256", 2048).is_err());
}

#[test]
fn self_signed_certificates_are_published_as_x5c() {
    use rustid_core::keys::{KeyOrigin, LoadedKey, generate_pkcs8, self_signed_certificate};
    let now = chrono::Utc::now();
    let pkcs8 = generate_pkcs8("RS256", 2048).unwrap();
    let cert = self_signed_certificate(
        "RS256",
        &pkcs8,
        "https://idsrv.test",
        now,
        now + chrono::Duration::days(104),
    )
    .unwrap();
    let key =
        LoadedKey::from_der("k", "RS256", &pkcs8, Some(&cert), &KeyOrigin::default()).unwrap();
    assert!(key.has_certificate());
    assert_eq!(key.jwk.x5t.as_ref().unwrap().len(), 27, "base64url SHA-1");
    // The certificate carries the subject: DER contains the UTF-8 issuer.
    assert!(cert.windows(18).any(|w| w == b"https://idsrv.test"));
    let ec = generate_pkcs8("ES256", 2048).unwrap();
    assert!(
        self_signed_certificate("ES256", &ec, "x", now, now).is_err(),
        "EC certificates are unsupported"
    );
    let other = generate_pkcs8("RS256", 2048).unwrap();
    assert!(
        LoadedKey::from_der("k", "RS256", &other, Some(&cert), &KeyOrigin::default()).is_err(),
        "a certificate for another key is refused"
    );
}
