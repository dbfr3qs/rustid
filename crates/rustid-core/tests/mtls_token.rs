//! Certificate-bound tokens (RFC 8705): the `cnf` a certificate secret
//! binds, ephemeral certificates, DPoP with mTLS, and the refresh token
//! rules for certificates.

mod support;

use chrono::Utc;
use rustid_core::authorize::code::AuthorizationCode;
use rustid_core::authorize::validate;
use rustid_core::client_certificate::ClientCertificate;
use rustid_core::clients::Client;
use rustid_core::form::Form;
use rustid_core::jwt::Jws;
use rustid_core::params::Params;
use rustid_core::session::{SignIn, UserSession};
use rustid_core::token::{TokenFailure, TokenResponse, process};
use serde_json::{Value, json};
use support::Fixture;

fn certificate(cn: &str) -> ClientCertificate {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let der = params.self_signed(&key).unwrap().der().to_vec();
    ClientCertificate::parse(&der, None).unwrap()
}

fn fixture(cert: &ClientCertificate) -> Fixture {
    let mut f = Fixture::new();
    let thumbprint = cert.thumbprint.clone();
    f.edit_clients(|clients| {
        let client = |value: Value| serde_json::from_value::<Client>(value).unwrap();
        clients.push(client(json!({
            "clientId": "mtls",
            "clientSecrets": [{ "type": "X509Thumbprint", "value": thumbprint }],
            "allowedGrantTypes": ["client_credentials", "authorization_code"],
            "redirectUris": ["https://mtls/callback"],
            "requirePkce": false,
            "allowOfflineAccess": true,
            "allowedScopes": ["openid", "api1"],
        })));
        clients.push(client(json!({
            "clientId": "public",
            "requireClientSecret": false,
            "allowedGrantTypes": ["authorization_code"],
            "redirectUris": ["https://public/callback"],
            "requirePkce": false,
            "allowOfflineAccess": true,
            "allowedScopes": ["openid", "api1"],
        })));
    });
    f
}

async fn request(
    f: &Fixture,
    cert: Option<&ClientCertificate>,
    proof: Option<&str>,
    pairs: &[(&str, &str)],
) -> Result<TokenResponse, TokenFailure> {
    let proofs: Vec<&str> = proof.into_iter().collect();
    let mut ctx = f.ctx(Utc::now());
    ctx.client_certificate = cert;
    ctx.dpop_proofs = &proofs;
    process(&ctx, None, &Form::from_pairs(pairs)).await
}

fn cnf(response: &TokenResponse) -> Option<Value> {
    Jws::decode(&response.access_token)
        .unwrap()
        .payload
        .get("cnf")
        .cloned()
}

fn error(result: Result<TokenResponse, TokenFailure>) -> (String, Option<String>) {
    match result {
        Err(TokenFailure::Protocol(e)) => (e.error.into_owned(), e.description),
        other => panic!("expected an error, got {other:?}"),
    }
}

const MTLS_CC: &[(&str, &str)] = &[
    ("grant_type", "client_credentials"),
    ("client_id", "mtls"),
    ("scope", "api1"),
];

const SECRET_CC: &[(&str, &str)] = &[
    ("grant_type", "client_credentials"),
    ("client_id", "client"),
    ("client_secret", "secret"),
    ("scope", "api1"),
];

#[tokio::test]
async fn a_certificate_secret_binds_the_token() {
    let cert = certificate("mtls");
    let f = fixture(&cert);
    let r = request(&f, Some(&cert), None, MTLS_CC).await.unwrap();
    assert_eq!(r.token_type, "Bearer");
    assert_eq!(cnf(&r), Some(json!({ "x5t#S256": cert.x5t_s256 })));
}

#[tokio::test]
async fn an_ephemeral_certificate_binds_only_when_always_emitted() {
    let cert = certificate("ephemeral");
    let mut f = fixture(&cert);
    let r = request(&f, Some(&cert), None, SECRET_CC).await.unwrap();
    assert_eq!(cnf(&r), None);
    f.options.mutual_tls.always_emit_confirmation_claim = true;
    let r = request(&f, Some(&cert), None, SECRET_CC).await.unwrap();
    assert_eq!(cnf(&r), Some(json!({ "x5t#S256": cert.x5t_s256 })));
}

#[tokio::test]
async fn dpop_takes_precedence_and_names_the_mtls_alias() {
    let cert = certificate("mtls");
    let f = fixture(&cert);
    let key = support::key("client-jwt-key.pem", "p", "RS256");
    // With a certificate, the proof is for the mTLS token endpoint.
    let plain = support::dpop_proof(&key, "http://h/connect/token", None);
    assert_eq!(
        error(request(&f, Some(&cert), Some(&plain), MTLS_CC).await),
        (
            "invalid_dpop_proof".into(),
            Some("Invalid 'htu' value.".into())
        )
    );
    let alias = support::dpop_proof(&key, "http://h/connect/mtls/token", None);
    let r = request(&f, Some(&cert), Some(&alias), MTLS_CC)
        .await
        .unwrap();
    assert_eq!(r.token_type, "DPoP");
    assert_eq!(
        cnf(&r),
        Some(json!({ "jkt": support::dpop_thumbprint(&key) }))
    );
}

/// A code for `client_id`, redeemed with `cert`.
async fn code_tokens(
    f: &Fixture,
    client_id: &str,
    cert: Option<&ClientCertificate>,
) -> Result<TokenResponse, TokenFailure> {
    let now = Utc::now();
    let query = format!(
        "client_id={client_id}&redirect_uri=https%3A%2F%2F{client_id}%2Fcallback&response_type=code&scope=openid%20api1%20offline_access&state=s&nonce=n"
    );
    let session = UserSession::sign_in(
        SignIn {
            subject_id: "bob".into(),
            ..Default::default()
        },
        None,
        now,
        3600,
    );
    let request_ = validate(
        &f.authorize_ctx(now),
        Params::parse_query(&query),
        Some(&session),
    )
    .await
    .unwrap();
    let handle = AuthorizationCode::for_request(&request_, now)
        .store(f.stores.grants.as_ref())
        .await
        .unwrap();
    let redirect = format!("https://{client_id}/callback");
    request(
        f,
        cert,
        None,
        &[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", &handle),
            ("redirect_uri", &redirect),
        ],
    )
    .await
}

async fn refresh(
    f: &Fixture,
    client_id: &str,
    cert: Option<&ClientCertificate>,
    token: &str,
) -> Result<TokenResponse, TokenFailure> {
    request(
        f,
        cert,
        None,
        &[
            ("grant_type", "refresh_token"),
            ("client_id", client_id),
            ("refresh_token", token),
        ],
    )
    .await
}

#[tokio::test]
async fn a_certificate_bound_refresh_token_needs_the_certificate() {
    let cert = certificate("mtls");
    let f = fixture(&cert);
    let rt = code_tokens(&f, "mtls", Some(&cert))
        .await
        .unwrap()
        .refresh_token
        .unwrap();
    // Without the certificate the client can't even authenticate.
    assert_eq!(
        error(refresh(&f, "mtls", None, &rt).await).0,
        "invalid_client"
    );
    let renewed = refresh(&f, "mtls", Some(&cert), &rt).await.unwrap();
    assert_eq!(cnf(&renewed), Some(json!({ "x5t#S256": cert.x5t_s256 })));
}

#[tokio::test]
async fn a_public_client_must_keep_its_certificate() {
    let cert = certificate("public");
    let mut f = fixture(&cert);
    f.options.mutual_tls.always_emit_confirmation_claim = true;
    let r = code_tokens(&f, "public", Some(&cert)).await.unwrap();
    assert_eq!(cnf(&r), Some(json!({ "x5t#S256": cert.x5t_s256 })));
    let rt = r.refresh_token.unwrap();
    assert_eq!(
        error(refresh(&f, "public", None, &rt).await),
        (
            "invalid_request".into(),
            Some("Proof of possession was used to obtain the initial refresh token and is required for subsequent token requests.".into())
        )
    );
    assert_eq!(
        error(refresh(&f, "public", Some(&certificate("other")), &rt).await),
        (
            "invalid_request".into(),
            Some("The client certificate in the refresh token request does not match the original used.".into())
        )
    );
    assert!(refresh(&f, "public", Some(&cert), &rt).await.is_ok());

    // A certificate-bound token can't switch to DPoP.
    let key = support::key("client-jwt-key.pem", "p", "RS256");
    let proof = support::dpop_proof(&key, "http://h/connect/mtls/token", None);
    let mut ctx = f.ctx(Utc::now());
    let proofs = [proof.as_str()];
    ctx.client_certificate = Some(&cert);
    ctx.dpop_proofs = &proofs;
    let switched = process(
        &ctx,
        None,
        &Form::from_pairs(&[
            ("grant_type", "refresh_token"),
            ("client_id", "public"),
            ("refresh_token", &rt),
        ]),
    )
    .await;
    assert_eq!(
        error(switched),
        (
            "invalid_request".into(),
            Some("Different proof of possession styles can't be mixed.".into())
        )
    );
}
