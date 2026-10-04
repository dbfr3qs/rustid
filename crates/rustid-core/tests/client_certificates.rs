//! Client certificates (RFC 8705): thumbprints and subject names, chain trust, and client authentication by certificate
//! (the mutual tls secret parser, the X.509 thumbprint secret validator,
//! the X.509 name secret validator).

mod support;

use aws_lc_rs::digest;
use chrono::Utc;
use rustid_core::client_certificate::{ClientCaRoots, ClientCertificate};
use rustid_core::clients::Client;
use rustid_core::form::Form;
use rustid_core::jwt::b64url;
use serde_json::json;
use support::Fixture;

struct Certs {
    ca_pem: String,
    /// Issued by the CA: C=US, O=rustid, CN=mtls-client.
    issued: Vec<u8>,
    /// Self-signed with the same subject.
    self_signed: Vec<u8>,
}

fn subject(params: &mut rcgen::CertificateParams) {
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CountryName, "US");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "rustid");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "mtls-client");
}

fn certs() -> Certs {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "rustid test CA");
    ca_params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    subject(&mut params);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let issued = params.signed_by(&key, &ca).unwrap();

    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    subject(&mut params);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    let self_signed = params.self_signed(&key).unwrap();

    Certs {
        ca_pem: pem::encode(&pem::Pem::new("CERTIFICATE", ca.der().to_vec())),
        issued: issued.der().to_vec(),
        self_signed: self_signed.der().to_vec(),
    }
}

fn roots(certs: &Certs) -> ClientCaRoots {
    ClientCaRoots::from_pem(certs.ca_pem.as_bytes()).unwrap()
}

#[test]
fn thumbprints_and_subject_are_read_exactly() {
    let certs = certs();
    let cert = ClientCertificate::parse(&certs.issued, None).unwrap();
    let sha1 = digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &certs.issued);
    let hex: String = sha1.as_ref().iter().map(|b| format!("{b:02X}")).collect();
    assert_eq!(cert.thumbprint, hex);
    assert_eq!(
        cert.x5t_s256,
        b64url(digest::digest(&digest::SHA256, &certs.issued).as_ref())
    );
    assert_eq!(cert.subject, "CN=mtls-client, O=rustid, C=US");
    assert_eq!(cert.cnf(), json!({ "x5t#S256": cert.x5t_s256 }).to_string());
    assert!(ClientCertificate::parse(b"not a certificate", None).is_none());
}

#[test]
fn subject_values_are_quoted_exactly() {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationName, "Acme, Inc.");
    params
        .distinguished_name
        .push(rcgen::DnType::OrganizationalUnitName, "R&D");
    params
        .distinguished_name
        .push(rcgen::DnType::LocalityName, "Oslo");
    params
        .distinguished_name
        .push(rcgen::DnType::StateOrProvinceName, "Oslo");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "a \"quoted\" name");
    let der = params.self_signed(&key).unwrap().der().to_vec();
    assert_eq!(
        ClientCertificate::parse(&der, None).unwrap().subject,
        r#"CN="a ""quoted"" name", S=Oslo, L=Oslo, OU=R&D, O="Acme, Inc.""#
    );
}

#[test]
fn chain_trust_comes_from_the_client_ca_roots() {
    let certs = certs();
    let roots = roots(&certs);
    assert!(
        ClientCertificate::parse(&certs.issued, Some(&roots))
            .unwrap()
            .trusted
    );
    assert!(
        !ClientCertificate::parse(&certs.self_signed, Some(&roots))
            .unwrap()
            .trusted
    );
    assert!(
        !ClientCertificate::parse(&certs.issued, None)
            .unwrap()
            .trusted
    );
}

fn fixture(clients: Vec<serde_json::Value>) -> Fixture {
    let mut f = Fixture::new();
    f.edit_clients(|all| {
        all.extend(
            clients
                .into_iter()
                .map(|c| serde_json::from_value::<Client>(c).unwrap()),
        )
    });
    f
}

async fn authenticate(
    f: &Fixture,
    cert: Option<&ClientCertificate>,
    form: &[(&str, &str)],
) -> Result<rustid_core::client_auth::Authenticated, &'static str> {
    let mut ctx = f.ctx(Utc::now());
    ctx.client_certificate = cert;
    rustid_core::client_auth::authenticate(&ctx, None, &Form::from_pairs(form))
        .await
        .unwrap()
}

#[tokio::test]
async fn a_certificate_authenticates_by_thumbprint_or_trusted_name() {
    let certs = certs();
    let roots = roots(&certs);
    let issued = ClientCertificate::parse(&certs.issued, Some(&roots)).unwrap();
    let self_signed = ClientCertificate::parse(&certs.self_signed, Some(&roots)).unwrap();
    let f = fixture(vec![
        json!({
            "clientId": "by.thumbprint",
            "clientSecrets": [{ "type": "X509Thumbprint", "value": self_signed.thumbprint.to_lowercase() }],
            "allowedGrantTypes": ["client_credentials"],
        }),
        json!({
            "clientId": "by.name",
            "clientSecrets": [{ "type": "X509Name", "value": "CN=mtls-client, O=rustid, C=US" }],
            "allowedGrantTypes": ["client_credentials"],
        }),
    ]);

    let ok = authenticate(&f, Some(&self_signed), &[("client_id", "by.thumbprint")])
        .await
        .unwrap();
    assert_eq!(ok.client.client_id, "by.thumbprint");
    assert_eq!(ok.confirmation, Some(self_signed.cnf()));
    let last = serde_json::to_value(f.events.take().pop().unwrap()).unwrap();
    assert_eq!(last["Name"], "Client Authentication Success");
    assert_eq!(last["AuthenticationMethod"], "X509Certificate");

    assert_eq!(
        authenticate(&f, Some(&issued), &[("client_id", "by.thumbprint")])
            .await
            .unwrap_err(),
        "invalid_client"
    );
    let ok = authenticate(&f, Some(&issued), &[("client_id", "by.name")])
        .await
        .unwrap();
    assert_eq!(ok.confirmation, Some(issued.cnf()));
    // The same subject, self-signed: a name alone proves nothing.
    assert_eq!(
        authenticate(&f, Some(&self_signed), &[("client_id", "by.name")])
            .await
            .unwrap_err(),
        "invalid_client"
    );
    // No certificate: the client id alone.
    assert_eq!(
        authenticate(&f, None, &[("client_id", "by.name")])
            .await
            .unwrap_err(),
        "invalid_client"
    );
}

#[tokio::test]
async fn a_shared_secret_wins_over_a_certificate() {
    let certs = certs();
    let cert = ClientCertificate::parse(&certs.self_signed, None).unwrap();
    let f = Fixture::new();
    // `client` has a shared secret: the form's secret authenticates it and
    // the certificate is only ephemeral.
    let ok = authenticate(
        &f,
        Some(&cert),
        &[("client_id", "client"), ("client_secret", "secret")],
    )
    .await
    .unwrap();
    assert_eq!(ok.client.client_id, "client");
    assert_eq!(ok.confirmation, None);
}

#[tokio::test]
async fn a_certificate_outside_its_validity_period_is_refused() {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2021, 1, 1);
    let der = params.self_signed(&key).unwrap().der().to_vec();
    let expired = ClientCertificate::parse(&der, None).unwrap();
    assert!(!expired.valid_at(Utc::now()));
    let f = fixture(vec![json!({
        "clientId": "expired",
        "clientSecrets": [{ "type": "X509Thumbprint", "value": expired.thumbprint }],
        "allowedGrantTypes": ["client_credentials"],
    })]);
    assert_eq!(
        authenticate(&f, Some(&expired), &[("client_id", "expired")])
            .await
            .unwrap_err(),
        "invalid_client"
    );
}
