//! A protected resource (the local API authentication handler in
//! `DPoPAndBearer` mode, for conformance runs): bearer
//! tokens, and DPoP-bound tokens with a proof bound to them.

mod support;

use chrono::Utc;
use rustid_core::clients::Client;
use rustid_core::form::Form;
use rustid_core::keys::LoadedKey;
use rustid_core::protected_resource::{Challenge, ResourceRequest, authenticate};
use rustid_core::token::process;
use serde_json::{Value, json};
use support::Fixture;

const RESOURCE: &str = "http://h/fapi2/resource";

fn rsa() -> LoadedKey {
    support::key("client-jwt-key.pem", "p", "RS256")
}

fn fixture() -> Fixture {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        clients.push(
            serde_json::from_value::<Client>(json!({
                "clientId": "client1",
                "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
                "allowedGrantTypes": ["client_credentials"],
                "allowedScopes": ["api1"],
            }))
            .unwrap(),
        );
    });
    f
}

/// An access token for client1, bound to `key` when given.
async fn token(f: &Fixture, key: Option<&LoadedKey>) -> String {
    let proof = key.map(|k| support::dpop_proof(k, "http://h/connect/token", None));
    let proofs: Vec<&str> = proof.as_deref().into_iter().collect();
    let mut ctx = f.ctx(Utc::now());
    ctx.dpop_proofs = &proofs;
    process(
        &ctx,
        None,
        &Form::from_pairs(&[
            ("grant_type", "client_credentials"),
            ("client_id", "client1"),
            ("client_secret", "secret"),
            ("scope", "api1"),
        ]),
    )
    .await
    .unwrap()
    .access_token
}

async fn call(
    f: &Fixture,
    authorization: Option<&str>,
    proofs: &[String],
    method: &str,
) -> Result<String, Challenge> {
    authenticate(
        &f.validation_ctx(Utc::now()),
        &ResourceRequest {
            authorization,
            dpop_proofs: proofs,
            method,
            url: RESOURCE,
            client_certificate: None,
        },
        &f.protector,
    )
    .await
    .unwrap()
}

fn dpop_error(result: Result<String, Challenge>) -> String {
    let challenge = result.expect_err("refused");
    let (error, description) = challenge.dpop_error.expect("a DPoP error");
    assert_eq!(error, "invalid_dpop_proof");
    description.unwrap_or_default()
}

#[tokio::test]
async fn a_bound_token_with_its_proof_is_served() {
    let f = fixture();
    let key = rsa();
    let at = token(&f, Some(&key)).await;
    let proof = support::dpop_resource_proof(&key, "GET", RESOURCE, Some(&at));
    let auth = format!("DPoP {at}");
    assert_eq!(
        call(&f, Some(&auth), std::slice::from_ref(&proof), "GET").await,
        Ok("client1".to_owned())
    );
    // The same proof again is a replay.
    assert!(!dpop_error(call(&f, Some(&auth), &[proof], "GET").await).is_empty());
    // A proof for another method or URL.
    let post = support::dpop_resource_proof(&key, "POST", RESOURCE, Some(&at));
    assert!(call(&f, Some(&auth), &[post], "GET").await.is_err());
    let elsewhere = support::dpop_resource_proof(&key, "GET", "http://h/other", Some(&at));
    assert!(call(&f, Some(&auth), &[elsewhere], "GET").await.is_err());
    // A proof by another key, even with the right hash.
    let thief = support::key("client-jwt-ec-key.pem", "p", "ES256");
    let stolen = support::dpop_resource_proof(&thief, "GET", RESOURCE, Some(&at));
    assert_eq!(
        dpop_error(call(&f, Some(&auth), &[stolen], "GET").await),
        "Invalid 'cnf' value."
    );
    // No proof, or two.
    assert!(call(&f, Some(&auth), &[], "GET").await.is_err());
    let one = support::dpop_resource_proof(&key, "GET", RESOURCE, Some(&at));
    let two = support::dpop_resource_proof(&key, "GET", RESOURCE, Some(&at));
    assert_eq!(
        dpop_error(call(&f, Some(&auth), &[one, two], "GET").await),
        "Too many DPoP headers provided."
    );
}

#[tokio::test]
async fn a_bound_token_is_never_served_as_a_bearer_token() {
    let f = fixture();
    let at = token(&f, Some(&rsa())).await;
    let challenge = call(&f, Some(&format!("Bearer {at}")), &[], "GET")
        .await
        .expect_err("refused");
    assert_eq!(
        challenge.bearer_error,
        Some((
            "invalid_token".to_owned(),
            Some("Must use DPoP when using an access token with a 'cnf' claim".to_owned())
        ))
    );
}

#[tokio::test]
async fn bearer_tokens_and_challenges() {
    let f = fixture();
    let at = token(&f, None).await;
    assert_eq!(
        call(&f, Some(&format!("Bearer {at}")), &[], "GET").await,
        Ok("client1".to_owned())
    );
    let none = call(&f, None, &[], "GET").await.expect_err("refused");
    assert_eq!(none.www_authenticate(), "Bearer, DPoP");
    // An invalid token fails without an error in the challenge.
    let bad = call(&f, Some("Bearer nonsense"), &[], "GET")
        .await
        .expect_err("refused");
    assert_eq!(bad.www_authenticate(), "Bearer, DPoP");
    let dpop = Challenge {
        bearer_error: None,
        dpop_error: Some((
            "invalid_dpop_proof".into(),
            Some("Invalid 'ath' value.".into()),
        )),
        dpop_nonce: None,
    };
    assert_eq!(
        dpop.www_authenticate(),
        "Bearer, DPoP error=\"invalid_dpop_proof\", error_description=\"Invalid 'ath' value.\""
    );
    let _ = Value::Null;
}

fn certificate(cn: &str) -> rustid_core::client_certificate::ClientCertificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let der = params.self_signed(&key).unwrap().der().to_vec();
    rustid_core::client_certificate::ClientCertificate::parse(&der, None).unwrap()
}

#[tokio::test]
async fn a_certificate_bound_token_is_served_with_its_certificate() {
    // RFC 8705: a token bound to a client certificate (cnf x5t#S256) is a
    // bearer token over a connection presenting that certificate.
    let cert = certificate("client");
    let mut f = fixture();
    let thumbprint = cert.thumbprint.clone();
    f.edit_clients(|clients| {
        clients.push(
            serde_json::from_value::<Client>(json!({
                "clientId": "mtls",
                "clientSecrets": [{ "type": "X509Thumbprint", "value": thumbprint }],
                "allowedGrantTypes": ["client_credentials"],
                "allowedScopes": ["api1"],
            }))
            .unwrap(),
        );
    });
    let mut ctx = f.ctx(Utc::now());
    ctx.client_certificate = Some(&cert);
    let at = process(
        &ctx,
        None,
        &Form::from_pairs(&[
            ("grant_type", "client_credentials"),
            ("client_id", "mtls"),
            ("scope", "api1"),
        ]),
    )
    .await
    .unwrap()
    .access_token;
    let bearer = format!("Bearer {at}");
    assert_eq!(
        served(&f, &bearer, Some(&cert)).await,
        Ok("mtls".to_owned())
    );
    let other = certificate("someone else");
    for refused in [
        served(&f, &bearer, Some(&other)).await,
        served(&f, &bearer, None).await,
    ] {
        let challenge = refused.expect_err("refused");
        assert_eq!(challenge.bearer_error.unwrap().0, "invalid_token");
    }
}

async fn served(
    f: &Fixture,
    authorization: &str,
    certificate: Option<&rustid_core::client_certificate::ClientCertificate>,
) -> Result<String, Challenge> {
    authenticate(
        &f.validation_ctx(Utc::now()),
        &ResourceRequest {
            authorization: Some(authorization),
            dpop_proofs: &[],
            method: "GET",
            url: RESOURCE,
            client_certificate: certificate,
        },
        &f.protector,
    )
    .await
    .unwrap()
}
