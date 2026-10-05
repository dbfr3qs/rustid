use rustid_core::form::{Form, FormError};

#[test]
fn decodes_plus_percent_escapes_and_keeps_invalid_escapes() {
    let form = Form::parse(b"a=x+y&b=%41%2b&c=%zz%4&d").unwrap();
    assert_eq!(form.first("a"), Some("x y"));
    assert_eq!(form.first("b"), Some("A+"));
    assert_eq!(form.first("c"), Some("%zz%4"));
    assert_eq!(form.first("d"), Some(""));
}

#[test]
fn invalid_utf8_becomes_a_replacement_character() {
    assert_eq!(Form::parse(b"s=%FF").unwrap().first("s"), Some("\u{FFFD}"));
}

#[test]
fn nul_in_a_key_or_value_is_rejected() {
    assert_eq!(Form::parse(b"a=%00"), Err(FormError::Nul));
    assert_eq!(Form::parse(b"a%00=1"), Err(FormError::Nul));
}

#[test]
fn get_drops_blank_values_and_joins_the_rest_with_commas() {
    let form = Form::parse(b"s=api1&s=%0A&s=api2&e=%20").unwrap();
    assert_eq!(form.get("s").as_deref(), Some("api1,api2"));
    assert_eq!(form.get("e"), None);
    assert_eq!(form.get("missing"), None);
    assert_eq!(form.first("e"), Some(" "), "first() returns the raw value");
}

#[test]
fn form_limits_are_enforced() {
    let many: String = (0..1025)
        .map(|i| format!("k{i}=v"))
        .collect::<Vec<_>>()
        .join("&");
    assert_eq!(Form::parse(many.as_bytes()), Err(FormError::TooManyValues));
    let at_limit: String = (0..1024)
        .map(|i| format!("k{i}=v"))
        .collect::<Vec<_>>()
        .join("&");
    assert!(Form::parse(at_limit.as_bytes()).is_ok());
    let long_key = format!("{}=v", "k".repeat(2049));
    assert_eq!(Form::parse(long_key.as_bytes()), Err(FormError::KeyTooLong));
    assert!(Form::parse(format!("{}=v", "k".repeat(2048)).as_bytes()).is_ok());
}

#[test]
fn keys_match_case_insensitively() {
    let form = Form::parse(b"GRANT_TYPE=client_credentials&Scope=a&scope=b").unwrap();
    assert_eq!(form.first("grant_type"), Some("client_credentials"));
    assert_eq!(form.get("SCOPE").as_deref(), Some("a,b"));
}
