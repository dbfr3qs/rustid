use rustid_core::federation::provider::*;
use rustid_core::federation::session::{select_claims, subject_for};

fn provider(json: serde_json::Value) -> IdentityProvider {
    serde_json::from_value(json).unwrap()
}
fn examplecorp() -> serde_json::Value {
    serde_json::json!({ "scheme": "examplecorp", "displayName": "Example Corp",
        "authority": "https://login.example.com/t/v2.0", "clientId": "abc",
        "clientAuthentication": { "secretEnv": "EXAMPLECORP_SECRET" } })
}

#[test]
fn defaults() {
    let p = provider(examplecorp());
    assert!(p.enabled);
    assert_eq!(p.scopes, ["openid", "profile", "email"]);
    assert_eq!(
        p.client_authentication.method,
        ClientAuthMethod::ClientSecretBasic
    );
    assert!(p.claims.contains(&"email".to_owned()));
    p.validate(false).unwrap();
}

#[test]
fn unknown_fields_are_refused() {
    let mut j = examplecorp();
    j["multiTenant"] = true.into();
    assert!(serde_json::from_value::<IdentityProvider>(j).is_err());
}

#[test]
fn validation_rules() {
    let bad = |edit: &dyn Fn(&mut serde_json::Value), loopback: bool| {
        let mut j = examplecorp();
        edit(&mut j);
        provider(j).validate(loopback).unwrap_err()
    };
    assert_eq!(
        bad(&|j| j["scheme"] = "Example Corp".into(), false),
        ProviderError::Scheme("Example Corp".into())
    );
    assert_eq!(
        bad(&|j| j["scheme"] = "-x".into(), false),
        ProviderError::Scheme("-x".into())
    );
    assert_eq!(
        bad(&|j| j["scheme"] = "local".into(), false),
        ProviderError::Reserved
    );
    for (edit, needle) in [
        (
            Box::new(|j: &mut serde_json::Value| j["authority"] = "http://login.example.com".into())
                as Box<dyn Fn(&mut serde_json::Value)>,
            "https",
        ),
        (
            Box::new(|j: &mut serde_json::Value| j["displayName"] = "".into()),
            "displayName",
        ),
        (
            Box::new(|j: &mut serde_json::Value| j["clientId"] = "".into()),
            "clientId",
        ),
        (
            Box::new(|j: &mut serde_json::Value| j["scopes"] = serde_json::json!(["profile"])),
            "openid",
        ),
        (
            Box::new(|j: &mut serde_json::Value| {
                j["clientAuthentication"] = serde_json::json!({"secret": "s", "secretEnv": "E"})
            }),
            "secret",
        ),
        (
            Box::new(|j: &mut serde_json::Value| j["clientAuthentication"] = serde_json::json!({})),
            "secret",
        ),
        (
            Box::new(|j: &mut serde_json::Value| {
                j["clientAuthentication"] = serde_json::json!({"method": "private_key_jwt"})
            }),
            "keyFile",
        ),
        (
            Box::new(
                |j: &mut serde_json::Value| j["clientAuthentication"] = serde_json::json!({"method": "private_key_jwt", "keyFile": "k.pem", "keyId": "k1", "algorithm": "HS256"}),
            ),
            "algorithm",
        ),
    ] {
        match bad(&*edit, false) {
            ProviderError::Invalid { scheme, message } => {
                assert_eq!(scheme, "examplecorp");
                assert!(message.contains(needle), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }
    let mut j = examplecorp();
    j["authority"] = "http://localhost:5444".into();
    provider(j.clone()).validate(true).unwrap();
    assert!(provider(j).validate(false).is_err());
}

#[test]
fn allowed_urls() {
    assert!(is_allowed_url("https://x.example", false));
    assert!(!is_allowed_url("http://x.example", true));
    assert!(is_allowed_url("http://localhost:1/a", true));
    assert!(is_allowed_url("http://127.0.0.1/a", true));
    assert!(!is_allowed_url("http://localhost.evil.example/", true));
    assert!(!is_allowed_url("ftp://x", true));
}

fn secret_provider(scheme: &str, enabled: bool) -> Provider {
    let mut j = examplecorp();
    j["scheme"] = scheme.into();
    j["enabled"] = enabled.into();
    Provider {
        config: provider(j),
        credential: Credential::Basic("s".into()),
    }
}

#[test]
fn providers_find_and_filter_by_client() {
    let ps = Providers::new(vec![
        secret_provider("a", true),
        secret_provider("b", true),
        secret_provider("off", false),
    ])
    .unwrap();
    assert!(ps.find("a").is_some());
    assert!(ps.find("off").is_none());
    assert!(ps.find("nope").is_none());
    let mut client: rustid_core::clients::Client =
        serde_json::from_value(serde_json::json!({"clientId": "c"})).unwrap();
    let schemes = |ps: &Providers, c: &rustid_core::clients::Client| {
        ps.allowed_for(c)
            .iter()
            .map(|p| p.config.scheme.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(schemes(&ps, &client), ["a", "b"]);
    client.identity_provider_restrictions = vec!["b".into(), "missing".into()];
    assert_eq!(schemes(&ps, &client), ["b"]);
    assert_eq!(
        Providers::new(vec![secret_provider("a", true), secret_provider("a", true)]).unwrap_err(),
        ProviderError::Duplicate("a".into())
    );
}

#[test]
fn subject_is_the_hash_of_issuer_and_sub() {
    // Known answer: base64url(SHA-256("https://a" 0x00 "123")).
    let expected = {
        use base64::Engine;
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"https://a\x00123");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(d.as_ref())
    };
    assert_eq!(subject_for("https://a", "123"), expected);
    assert_eq!(subject_for("https://a", "123").len(), 43);
    // The separator matters: ("ab", "c") and ("a", "bc") differ.
    assert_ne!(subject_for("ab", "c"), subject_for("a", "bc"));
}

#[test]
fn claim_selection_drops_protocol_claims_even_when_asked() {
    let payload = serde_json::json!({ "iss": "i", "sub": "s", "aud": "a", "nonce": "n", "tid": "t",
        "name": "Ada", "email": "ada@example.com", "email_verified": true, "groups": ["x", "y"] });
    let claims = select_claims(
        payload.as_object().unwrap(),
        &[
            "name".into(),
            "email_verified".into(),
            "groups".into(),
            "iss".into(),
            "tid".into(),
        ],
    );
    let pairs: Vec<(String, String)> = claims
        .iter()
        .map(|c| (c.claim_type.clone(), c.value.clone()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("name".into(), "Ada".into()),
            ("email_verified".into(), "true".into()),
            ("groups".into(), "x".into()),
            ("groups".into(), "y".into())
        ]
    );
}
