//! Writes rustid-signed SAML documents for an external signature verifier
//! to check. Usage:

use std::path::Path;

use rustid_saml::xml::dom::Limits;
use rustid_saml::xml::dsig::{Credential, sign};

const RESPONSE: &str = r#"<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2026-10-01T10:00:00Z" Destination="https://sp.example/acs?a=1&amp;b=2" InResponseTo="_req1"><saml:Issuer>https://idp.example</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assert1" Version="2.0" IssueInstant="2026-10-01T10:00:00Z"><saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID></saml:Subject><saml:AttributeStatement>ATTRIBUTES</saml:AttributeStatement></saml:Assertion></samlp:Response>"#;

fn attribute(name: &str, value: &str) -> String {
    format!(
        r#"<saml:Attribute Name="{name}"><saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">{value}</saml:AttributeValue></saml:Attribute>"#
    )
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let keys = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    std::fs::create_dir_all(out).unwrap();
    let read = |name: &str| std::fs::read_to_string(keys.join(name)).unwrap();
    let special = attribute(
        "special",
        "&amp; &lt;tag&gt; \"quotes\" 'apostrophes' é€😀 line\nbreak",
    ) + &attribute("name", "Alice O&apos;Brien");
    let payload: String = (0..200)
        .map(|i| attribute(&format!("claim{i}"), &"x".repeat(200)))
        .collect();
    for key in ["rsa", "ec256", "ec384"] {
        let credential = Credential::from_pem(
            &read(&format!("{key}.cert.pem")),
            &read(&format!("{key}.key.pem")),
        )
        .unwrap();
        for (name, attributes) in [
            ("response", attribute("email", "alice@example.com")),
            ("special", special.clone()),
            ("payload", payload.clone()),
        ] {
            let text = RESPONSE.replace("ATTRIBUTES", &attributes);
            let limits = Limits {
                max_size: 4_000_000,
                ..Limits::default()
            };
            let once = sign(&text, "_assert1", &credential, &limits).unwrap();
            let both = sign(&once, "_resp1", &credential, &limits).unwrap();
            std::fs::write(out.join(format!("{key}-{name}.xml")), both).unwrap();
        }
        // A response as rustid-saml::response writes and signs it.
        let response = written_response();
        let xml = rustid_saml::response::write_response(&response);
        let signed =
            rustid_saml::response::sign_response(&xml, &response, true, true, &credential).unwrap();
        std::fs::write(out.join(format!("{key}-written.xml")), signed).unwrap();
    }
    // A redirect query, signed as rustid signs logout requests.
    let rsa = Credential::from_pem(&read("rsa.cert.pem"), &read("rsa.key.pem")).unwrap();
    let query = rustid_saml::bindings::redirect::encode(
        rustid_saml::bindings::MessageName::SamlRequest,
        "<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"_l\"/>",
        Some("state with spaces/ü"),
        Some(&rsa),
    )
    .unwrap();
    std::fs::write(
        out.join("rsa-redirect.query"),
        query.trim_start_matches('?'),
    )
    .unwrap();
    println!("wrote {}", out.display());
}

fn written_response() -> rustid_saml::response::Response {
    use rustid_saml::response::*;
    let now = chrono::Utc::now();
    Response {
        id: "_resp1".into(),
        issue_instant: now,
        destination: Some("https://sp.example/acs".into()),
        in_response_to: Some("_req1".into()),
        issuer: "https://idp.example/Saml2".into(),
        status: Status::success(),
        assertion: Some(Assertion {
            id: "_assert1".into(),
            issue_instant: now,
            issuer: "https://idp.example/Saml2".into(),
            name_id: SubjectNameId {
                value: "alice & <co>".into(),
                format: Some(rustid_saml::constants::NAME_ID_UNSPECIFIED.into()),
                sp_name_qualifier: None,
                name_qualifier: None,
            },
            not_before: now,
            not_on_or_after: now + chrono::Duration::seconds(300),
            recipient: "https://sp.example/acs".into(),
            in_response_to: Some("_req1".into()),
            audience: "https://sp.example".into(),
            authn: AuthnStatement {
                authn_instant: now,
                session_index: Some("abc".into()),
                class_ref: rustid_saml::constants::AUTHN_CONTEXT_UNSPECIFIED.into(),
            },
            // Special characters and a 200-claim payload
            // (`callback_signature_*` rows).
            attributes: (0..200)
                .map(|i| (format!("claim{i}"), vec!["x".repeat(200)]))
                .chain([
                    ("email".into(), vec!["alice@example.com".into()]),
                    (
                        "roles".into(),
                        vec!["a".into(), String::new(), "\"quoted\" é".into()],
                    ),
                ])
                .collect(),
        }),
    }
}
