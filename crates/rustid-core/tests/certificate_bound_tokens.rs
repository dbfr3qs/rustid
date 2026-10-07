//! A client that requires certificate-bound tokens gets none without a
//! client certificate.

mod support;

use chrono::Utc;
use rustid_core::clients::Client;
use rustid_core::form::Form;
use rustid_core::token::{TokenError, TokenFailure, process};
use serde_json::json;
use support::Fixture;

fn certificate() -> rustid_core::client_certificate::ClientCertificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "bound");
    let der = params.self_signed(&key).unwrap().der().to_vec();
    rustid_core::client_certificate::ClientCertificate::parse(&der, None).unwrap()
}

fn fixture(require: bool) -> Fixture {
    let mut f = Fixture::new();
    f.edit_clients(|clients| {
        clients.push(
            serde_json::from_value::<Client>(json!({
                "clientId": "bound",
                "clientSecrets": [{ "value": "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=" }],
                "allowedGrantTypes": ["client_credentials"],
                "allowedScopes": ["api1"],
                "requireCertificateBoundTokens": require,
            }))
            .unwrap(),
        );
    });
    f
}

const REQUEST: [(&str, &str); 4] = [
    ("grant_type", "client_credentials"),
    ("client_id", "bound"),
    ("client_secret", "secret"),
    ("scope", "api1"),
];

#[tokio::test]
async fn without_a_certificate_the_request_is_refused() {
    let f = fixture(true);
    let refused = process(&f.ctx(Utc::now()), None, &Form::from_pairs(&REQUEST)).await;
    match refused {
        Err(TokenFailure::Protocol(TokenError { error, .. })) => {
            assert_eq!(error, "invalid_request")
        }
        other => panic!("{other:?}"),
    }
    let cert = certificate();
    let mut ctx = f.ctx(Utc::now());
    ctx.client_certificate = Some(&cert);
    let token = process(&ctx, None, &Form::from_pairs(&REQUEST))
        .await
        .unwrap();
    let jws = rustid_core::jwt::Jws::decode(&token.access_token).unwrap();
    assert!(
        jws.payload["cnf"]["x5t#S256"].is_string(),
        "bound to the certificate"
    );
}

#[tokio::test]
async fn a_client_that_doesnt_require_it_is_unchanged() {
    let f = fixture(false);
    assert!(
        process(&f.ctx(Utc::now()), None, &Form::from_pairs(&REQUEST))
            .await
            .is_ok()
    );
}
