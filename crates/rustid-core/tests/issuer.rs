use rustid_core::issuer::{RequestOrigin, current_issuer};
use rustid_core::options::ProtocolOptions;

fn origin(host: &str, base_path: &str) -> RequestOrigin {
    RequestOrigin {
        scheme: "http".into(),
        host: host.into(),
        base_path: base_path.into(),
    }
}

#[test]
fn configured_issuer_is_used_verbatim() {
    let options = ProtocolOptions {
        issuer_uri: Some("https://Idsrv.Test/X".into()),
        ..Default::default()
    };
    assert_eq!(
        current_issuer(&options, &origin("127.0.0.1:5001", "/ROOT")),
        "https://Idsrv.Test/X"
    );
}

#[test]
fn dynamic_issuer_is_origin_plus_base_path_lower_cased() {
    let options = ProtocolOptions::default();
    assert_eq!(
        current_issuer(&options, &origin("127.0.0.1:5001", "/ROOT")),
        "http://127.0.0.1:5001/root"
    );
}

#[test]
fn dynamic_issuer_keeps_case_when_lower_casing_is_disabled() {
    let options = ProtocolOptions {
        lower_case_issuer_uri: false,
        ..Default::default()
    };
    assert_eq!(
        current_issuer(&options, &origin("127.0.0.1:5001", "/ROOT")),
        "http://127.0.0.1:5001/ROOT"
    );
}

#[test]
fn punycode_host_becomes_unicode_in_the_issuer_but_not_in_the_base_url() {
    let options = ProtocolOptions::default();
    let request = origin("xn--80af5akm.xn--p1ai", "");
    assert_eq!(current_issuer(&options, &request), "http://грант.рф");
    assert_eq!(request.base_url(), "http://xn--80af5akm.xn--p1ai");
}

#[test]
fn port_survives_unicode_conversion() {
    assert_eq!(
        origin("xn--80af5akm.xn--p1ai:8443", "").unicode_origin(),
        "http://грант.рф:8443"
    );
    assert_eq!(
        origin("[::1]:8080", "").unicode_origin(),
        "http://[::1]:8080"
    );
}

#[test]
fn blank_configured_issuer_counts_as_missing() {
    let options = ProtocolOptions {
        issuer_uri: Some("  ".into()),
        ..Default::default()
    };
    assert_eq!(
        current_issuer(&options, &origin("localhost:1", "")),
        "http://localhost:1"
    );
}

#[test]
fn a_non_ascii_host_label_is_left_as_is() {
    // Hosts are ASCII from the wire, but the origin must not panic on a
    // label whose fourth byte falls inside a character.
    let origin = rustid_core::issuer::RequestOrigin {
        scheme: "https".into(),
        host: "abc\u{e9}x.example".into(),
        base_path: String::new(),
    };
    assert_eq!(origin.unicode_origin(), "https://abc\u{e9}x.example");
}
