use rustid_core::clients::{Client, ClientClaim};
use rustid_core::options::ProtocolOptions;
use rustid_core::scopes::ValidatedResources;
use rustid_core::tokens::{client_access_token, jwt_payload, new_jwt_id};
use serde_json::{Value, json};

fn resources(scopes: &[&str], audiences: &[&str]) -> ValidatedResources {
    ValidatedResources {
        scopes: scopes.iter().map(|s| s.to_string()).collect(),
        api_resources: audiences
            .iter()
            .map(|a| rustid_core::resources::ApiResource {
                name: a.to_string(),
                ..Default::default()
            })
            .collect(),
        ..Default::default()
    }
}

fn claim(t: &str, v: &str, vt: &str) -> ClientClaim {
    ClientClaim {
        claim_type: t.into(),
        value: v.into(),
        value_type: vt.into(),
    }
}

#[test]
fn payload_has_a_fixed_order_and_types() {
    let client = Client {
        client_id: "c".into(),
        access_token_lifetime: 120,
        claims: vec![
            claim("role", "a", "http://www.w3.org/2001/XMLSchema#string"),
            claim("role", "b", "http://www.w3.org/2001/XMLSchema#string"),
            claim("flag", "True", "http://www.w3.org/2001/XMLSchema#boolean"),
            claim("n", "42", "http://www.w3.org/2001/XMLSchema#integer"),
            claim("obj", r#"{"a":1}"#, "JSON"),
        ],
        ..Default::default()
    };
    let options = ProtocolOptions::default();
    let token = client_access_token(
        &options,
        "https://iss",
        &client,
        &resources(&["s1", "s2"], &["api"]),
    );
    let payload = jwt_payload(&options, &token, 1000, Some("J")).unwrap();
    let keys: Vec<&str> = payload.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        [
            "iss",
            "nbf",
            "iat",
            "exp",
            "aud",
            "scope",
            "client_id",
            "client_role",
            "client_flag",
            "client_n",
            "client_obj",
            "jti"
        ]
    );
    assert_eq!(
        Value::Object(payload),
        json!({ "iss": "https://iss", "nbf": 1000, "iat": 1000, "exp": 1120, "aud": "api", "scope": ["s1", "s2"], "client_id": "c",
                "client_role": ["a", "b"], "client_flag": true, "client_n": 42, "client_obj": { "a": 1 }, "jti": "J" })
    );
}

#[test]
fn options_change_scope_form_and_add_the_static_audience() {
    let options = ProtocolOptions {
        emit_scopes_as_space_delimited_string_in_jwt: true,
        emit_static_audience_claim: true,
        ..Default::default()
    };
    let client = Client {
        client_id: "c".into(),
        client_claims_prefix: None,
        ..Default::default()
    };
    let token = client_access_token(
        &options,
        "https://iss/",
        &client,
        &resources(&["s1", "offline_access", "s2"], &[]),
    );
    let payload = jwt_payload(&options, &token, 0, None).unwrap();
    assert_eq!(payload["scope"], "s1 s2");
    assert_eq!(payload["aud"], "https://iss/resources");
    assert!(!payload.contains_key("jti"));
}

#[test]
fn invalid_typed_claim_value_is_an_error() {
    let client = Client {
        client_id: "c".into(),
        claims: vec![claim("n", "x", "http://www.w3.org/2001/XMLSchema#integer")],
        ..Default::default()
    };
    let options = ProtocolOptions::default();
    let token = client_access_token(&options, "i", &client, &resources(&["s"], &[]));
    let err = jwt_payload(&options, &token, 0, None).unwrap_err();
    assert_eq!(err.claim_type, "client_n");
}

#[test]
fn jwt_ids_are_32_upper_case_hex_characters_and_unique() {
    let (a, b) = (new_jwt_id(), new_jwt_id());
    assert_eq!(a.len(), 32);
    assert!(
        a.chars()
            .all(|c| c.is_ascii_digit() || c.is_ascii_uppercase())
    );
    assert_ne!(a, b);
}

#[test]
fn double_claims_are_written_exactly() {
    let double = "http://www.w3.org/2001/XMLSchema#double";
    let client = Client {
        client_id: "c".into(),
        client_claims_prefix: Some(String::new()),
        claims: vec![claim("whole", "1.0", double), claim("half", "0.5", double)],
        ..Default::default()
    };
    let options = ProtocolOptions::default();
    let token = client_access_token(&options, "https://iss", &client, &resources(&[], &[]));
    let payload = jwt_payload(&options, &token, 1000, None).unwrap();
    let json = serde_json::to_string(&payload).unwrap();
    assert!(json.ends_with(r#""whole":1,"half":0.5}"#), "{json}");
}
