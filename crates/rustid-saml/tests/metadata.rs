//! IdP metadata, checked against
//! a verified document
//! and each metadata row.

use base64::Engine;
use chrono::{TimeZone, Utc};
use rustid_core::options::TimeSpan;
use rustid_saml::constants::{NAME_ID_EMAIL, NAME_ID_PERSISTENT};
use rustid_saml::metadata::{metadata_path, saml_issuer, write_metadata, xs_duration};
use rustid_saml::options::SamlOptions;

const CERT: &str = "MIICojCCAYqgAwIBAgIIIjGqKDo3ME4wDQYJKoZIhvcNAQELBQAwETEPMA0GA1UEAxMGZm9vYmFyMB4XDTI1MTExMDE0MTEyNloXDTMwMTExMDE0MTEyNlowETEPMA0GA1UEAxMGZm9vYmFyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu/fcM55jlB810lyxGpgk0Zhw83Liqz80l3zLLAZgJ/IUdBx9VFD28BeO37eByHDXxBIQdHFYXQj+lv2g3KFRxVzfZhiFUrb1UydJYFZ951sQUEsP4T/Fpbyb95HNrwG2NwE5/fk1MXr9no4ydsQTZA6EWOfbxn6o2YQs/8QdDykhCzpZcWYbk5AKS/G6nYLpwuW4UsyMQ6ur9ZQXtwDS/hGyP3RjK8pjqkckbQG9ZapI+hWezIJkGmkXcuIx+FpZbdjjwu/SIcNNrBIXLbrbWyxoWt4y2jWfDixanBAubBLtx6tCg69trJ3M5gZkFZBR3CVqs78fYZUThKBTS20afQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCxB08tE2bDWpF5mR14kQvRUA/2hZKeC6CYYGEwOu1hbh5m3rVj4T9GPgOh+s6tX+rCb0IoV1uD9iSeTd3XaJ/1sSFkgVD/PaA6NRgzKVeDXLl9rZGAnOmp/Es3Pz35FbPxZKTe8UDyFHySbioLaLvtODhzX7SeGP3BcRpp8rZLvggMYiqo3w39+qZcgZPIBP4yRSulBYb3r9qagQ/n//gp7SmenCQmjA5L7pTn7QggFQsSQmB6dyNS54cUk0niUsTihT9oqpMnXmsXonXf5cv3tnaydreiB4aPea+OjjY3oy8hvHUH6FuQQX7t3RllZlPGJQFZe61rYMVmRRjlHWTA";

fn cert() -> Vec<u8> {
    base64::engine::general_purpose::STANDARD
        .decode(CERT)
        .unwrap()
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2000, 1, 2, 3, 4, 5).unwrap()
}

fn scrub_id(xml: &str) -> String {
    let start = xml.find(" ID=\"").unwrap() + 5;
    let end = start + xml[start..].find('"').unwrap();
    format!("{}_SCRUBBED{}", &xml[..start], &xml[end..])
}

#[test]
fn the_default_document_matches_byte_for_byte() {
    let xml = write_metadata(
        &SamlOptions::default(),
        "_SCRUBBED",
        &[cert()],
        "https://localhost/",
        now(),
    );
    let expected = format!(
        r#"<md:EntityDescriptor ID="_SCRUBBED" entityID="_SCRUBBED" cacheDuration="PT12H" validUntil="2000-01-07T03:04:05Z" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true"><md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{CERT}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://localhost/Saml2/SLO" /><md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://localhost/Saml2/SLO" /><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://localhost/Saml2/SSO" /><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://localhost/Saml2/SSO" /></md:IDPSSODescriptor></md:EntityDescriptor>"#
    );
    assert_eq!(scrub_id(&xml), expected);
    // A fresh xs:ID each time.
    let again = write_metadata(
        &SamlOptions::default(),
        "x",
        &[],
        "https://localhost",
        now(),
    );
    assert_ne!(xml[..60].to_owned(), again[..60].to_owned(), "ids differ");
}

#[test]
fn options_shape_the_document() {
    let mut options = SamlOptions {
        want_authn_requests_signed: false,
        supported_name_id_formats: vec![NAME_ID_EMAIL.into(), NAME_ID_PERSISTENT.into()],
        ..Default::default()
    };
    options.metadata.expiry_duration = TimeSpan(30 * 86_400);
    options.metadata.cache_duration = TimeSpan(90 * 60);
    let certs = [cert(), vec![1, 2, 3]];
    let xml = write_metadata(
        &options,
        "https://idp.example/x",
        &certs,
        "https://idp.example",
        now(),
    );
    assert!(!xml.contains("WantAuthnRequestsSigned"), "{xml}");
    assert!(
        xml.contains(r#"validUntil="2000-02-01T03:04:05Z""#),
        "{xml}"
    );
    assert!(xml.contains(r#"cacheDuration="PT1H30M""#), "{xml}");
    assert!(xml.contains(r#"entityID="https://idp.example/x""#));
    assert_eq!(xml.matches("<md:KeyDescriptor use=\"signing\">").count(), 2);
    assert!(xml.contains("<ds:X509Certificate>AQID</ds:X509Certificate>"));
    assert_eq!(xml.matches("<md:NameIDFormat>").count(), 2);
    assert!(xml.contains(NAME_ID_PERSISTENT));
    for location in xml.split("Location=\"").skip(1) {
        let url = &location[..location.find('"').unwrap()];
        assert!(!url.ends_with('/'), "{url}");
        assert!(!url["https://".len()..].contains("//"), "{url}");
    }
}

#[test]
fn durations_are_xml_schema_durations() {
    assert_eq!(xs_duration(43_200), "PT12H");
    assert_eq!(xs_duration(432_000), "P5D");
    assert_eq!(xs_duration(0), "PT0S");
    assert_eq!(xs_duration(90 * 60 + 5), "PT1H30M5S");
    assert_eq!(xs_duration(86_400 + 1), "P1DT1S");
    assert_eq!(xs_duration(-60), "-PT1M");
}

#[test]
fn the_issuer_and_path_follow_the_entity_id() {
    let mut options = SamlOptions::default();
    assert_eq!(
        saml_issuer(&options, "https://idsrv.test"),
        "https://idsrv.test/Saml2"
    );
    assert_eq!(metadata_path(&options), "/Saml2");
    options.entity_id = Some("https://idp.example.com/custom/saml".into());
    assert_eq!(
        saml_issuer(&options, "https://idsrv.test"),
        "https://idp.example.com/custom/saml"
    );
    assert_eq!(metadata_path(&options), "/custom/saml");
    options.entity_id = Some("urn:my:custom:idp".into());
    assert_eq!(metadata_path(&options), "/Saml2");
    options.entity_id = Some("https://idp.example.com/".into());
    assert_eq!(metadata_path(&options), "/Saml2", "a root path falls back");
    options.entity_id = Some("https://idp.example.com".into());
    assert_eq!(metadata_path(&options), "/Saml2");
    options.entity_id = Some("ftp://idp.example.com/x".into());
    assert_eq!(metadata_path(&options), "/Saml2");
}
