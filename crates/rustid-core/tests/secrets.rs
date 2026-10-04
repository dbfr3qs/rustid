use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustid_core::clients::Secret;
use rustid_core::form::Form;
use rustid_core::options::InputLengthRestrictions;
use rustid_core::secrets::{
    ParsedSecret, ParsedSecretKind, parse, parse_basic, parse_jwt_bearer, parse_post_body,
    validate_shared_secret,
};

fn limits() -> InputLengthRestrictions {
    InputLengthRestrictions::default()
}

fn basic(pair: &str) -> String {
    format!("Basic {}", STANDARD.encode(pair))
}

fn shared(id: &str, secret: &str) -> ParsedSecret {
    ParsedSecret {
        id: id.into(),
        credential: Some(secret.into()),
        kind: ParsedSecretKind::SharedSecret,
    }
}

fn hashed(secret: &str, sha512: bool) -> Secret {
    use aws_lc_rs::digest;
    let alg = if sha512 {
        &digest::SHA512
    } else {
        &digest::SHA256
    };
    Secret {
        value: STANDARD.encode(digest::digest(alg, secret.as_bytes())),
        ..Default::default()
    }
}

#[test]
fn basic_parses_url_encoded_credentials_with_case_insensitive_scheme() {
    let header = format!("bAsIc {}", STANDARD.encode("my%3Aclient:s%2Bcr+t"));
    assert_eq!(
        parse_basic(Some(&header), &limits()),
        Some(shared("my:client", "s+cr t"))
    );
}

#[test]
fn basic_without_secret_is_a_client_id_only() {
    let parsed = parse_basic(Some(&basic("client:")), &limits()).unwrap();
    assert_eq!(parsed.kind, ParsedSecretKind::NoSecret);
    assert_eq!(parsed.credential, None);
}

#[test]
fn basic_rejects_garbage_and_oversized_values() {
    for header in [
        "Bearer abc",
        "Basic !!!",
        &basic("no-colon"),
        &basic(":secret"),
        &basic(&format!("{}:s", "c".repeat(101))),
    ] {
        assert_eq!(parse_basic(Some(header), &limits()), None, "{header}");
    }
    assert_eq!(
        parse_basic(Some(&format!("Basic {}", "A".repeat(900))), &limits()),
        None
    );
}

#[test]
fn post_body_reads_client_id_and_optional_secret() {
    let form = Form::from_pairs(&[("client_id", "c"), ("client_secret", "s")]);
    assert_eq!(parse_post_body(&form, &limits()), Some(shared("c", "s")));
    let form = Form::from_pairs(&[("client_id", "c")]);
    assert_eq!(
        parse_post_body(&form, &limits()).unwrap().kind,
        ParsedSecretKind::NoSecret
    );
    assert_eq!(
        parse_post_body(&Form::from_pairs(&[("client_secret", "s")]), &limits()),
        None
    );
}

#[test]
fn jwt_bearer_takes_the_client_id_from_the_unverified_sub() {
    let payload = rustid_core::jwt::b64url(br#"{"sub":"client.jwt"}"#);
    let assertion = format!("e30.{payload}.c2ln");
    let form = Form::from_pairs(&[
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", &assertion),
    ]);
    let parsed = parse_jwt_bearer(&form, &limits()).unwrap();
    assert_eq!(
        (parsed.id.as_str(), parsed.kind),
        ("client.jwt", ParsedSecretKind::JwtBearer)
    );
    let wrong_type = Form::from_pairs(&[
        ("client_assertion_type", "urn:other"),
        ("client_assertion", &assertion),
    ]);
    assert_eq!(parse_jwt_bearer(&wrong_type, &limits()), None);
}

#[test]
fn a_real_credential_beats_a_bare_client_id_and_jwt_parsing_needs_enabling() {
    let payload = rustid_core::jwt::b64url(br#"{"sub":"client.jwt"}"#);
    let assertion = format!("e30.{payload}.c2ln");
    let form = Form::from_pairs(&[
        ("client_id", "client.jwt"),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", &assertion),
    ]);
    assert_eq!(
        parse(None, &form, &limits(), true).unwrap().kind,
        ParsedSecretKind::JwtBearer
    );
    assert_eq!(
        parse(None, &form, &limits(), false).unwrap().kind,
        ParsedSecretKind::NoSecret
    );
    // Basic wins over the body when both carry a secret.
    let body = Form::from_pairs(&[("client_id", "b"), ("client_secret", "s")]);
    assert_eq!(
        parse(Some(&basic("a:s")), &body, &limits(), false)
            .unwrap()
            .id,
        "a"
    );
    assert_eq!(parse(None, &Form::default(), &limits(), true), None);
}

#[test]
fn shared_secrets_match_their_sha256_or_sha512_hash() {
    let (s256, s512) = (hashed("secret", false), hashed("secret", true));
    assert!(validate_shared_secret(&[&s256], &shared("c", "secret")));
    assert!(validate_shared_secret(&[&s512], &shared("c", "secret")));
    assert!(!validate_shared_secret(&[&s256], &shared("c", "wrong")));
    let no_secret = ParsedSecret {
        id: "c".into(),
        credential: None,
        kind: ParsedSecretKind::NoSecret,
    };
    assert!(!validate_shared_secret(&[&s256], &no_secret));
}

#[test]
fn a_stored_value_that_is_not_a_hash_fails_the_whole_validation() {
    let plain = Secret {
        value: "not-base64!".into(),
        ..Default::default()
    };
    let good = hashed("secret", false);
    assert!(!validate_shared_secret(
        &[&plain, &good],
        &shared("c", "secret")
    ));
    let jwk = Secret {
        value: "{}".into(),
        secret_type: "JWK".into(),
        ..Default::default()
    };
    assert!(
        validate_shared_secret(&[&jwk, &good], &shared("c", "secret")),
        "other secret types are skipped"
    );
}

#[test]
fn basic_header_with_a_character_across_the_scheme_boundary_is_not_basic() {
    // "a" then U+FFFD: byte 6 falls inside the replacement character.
    assert_eq!(parse_basic(Some("a\u{fffd}\u{fffd}"), &limits()), None);
    assert_eq!(parse_basic(Some("Basi\u{e9}c"), &limits()), None);
}
