use rustid_core::claims::{from_jwt_payload, to_dictionary};
use rustid_core::tokens::Claim;
use serde_json::json;

fn typed(t: &str, v: &str, vt: &str) -> Claim {
    Claim {
        claim_type: t.into(),
        value: v.into(),
        value_type: vt.into(),
    }
}

const INT: &str = "http://www.w3.org/2001/XMLSchema#integer";
const INT64: &str = "http://www.w3.org/2001/XMLSchema#integer64";
const BOOL: &str = "http://www.w3.org/2001/XMLSchema#boolean";
const DOUBLE: &str = "http://www.w3.org/2001/XMLSchema#double";

#[test]
fn values_convert_by_type_and_fall_back_to_strings() {
    let claims = [
        typed("a", "7", INT),
        typed("b", "9000000000", INT64),
        typed("c", "True", BOOL),
        typed("d", "1.5", DOUBLE),
        typed("e", "{\"x\":[1]}", "json"),
        typed("f", "[1,2]", "JSON"),
        typed("g", "seven", INT),
        typed("h", "{bad", "json"),
        Claim::string("i", "42"),
    ];
    assert_eq!(
        serde_json::Value::Object(to_dictionary(&claims)),
        json!({"a": 7, "b": 9000000000i64, "c": true, "d": 1.5, "e": {"x": [1]},
               "f": [1, 2], "g": "seven", "h": "{bad", "i": "42"})
    );
}

#[test]
fn repeated_types_become_lists_and_exact_duplicates_are_dropped() {
    let claims = [
        Claim::string("role", "a"),
        Claim::string("x", "1"),
        Claim::string("role", "b"),
        Claim::string("role", "a"),
        Claim::string("role", "c"),
        typed("arr", "[1]", "json"),
        typed("arr", "[2]", "json"),
        typed("arr", "[3]", "json"),
    ];
    assert_eq!(
        serde_json::Value::Object(to_dictionary(&claims)),
        json!({"role": ["a", "b", "c"], "x": "1", "arr": [[1], [2], [3]]})
    );
}

#[test]
fn a_json_array_value_is_wrapped_not_extended() {
    let claims = [typed("arr", "[1,2]", "json"), typed("arr", "3", INT)];
    assert_eq!(
        serde_json::Value::Object(to_dictionary(&claims)),
        json!({"arr": [[1, 2], 3]})
    );
}

#[test]
fn jwt_payloads_become_typed_claims() {
    let payload = json!({"iss": "i", "aud": ["a", "b"], "exp": 5, "f": true, "d": 0.5,
                         "o": {"k": 1}, "n": [[1], {"z": 2}]});
    let claims = from_jwt_payload(payload.as_object().unwrap());
    let flat: Vec<(&str, &str)> = claims
        .iter()
        .map(|c| (c.claim_type.as_str(), c.value.as_str()))
        .collect();
    assert_eq!(
        flat,
        [
            ("iss", "i"),
            ("aud", "a"),
            ("aud", "b"),
            ("exp", "5"),
            ("f", "true"),
            ("d", "0.5"),
            ("o", "{\"k\":1}"),
            ("n", "[1]"),
            ("n", "{\"z\":2}")
        ]
    );
    assert_eq!(
        serde_json::Value::Object(to_dictionary(&claims)),
        json!({"iss": "i", "aud": ["a", "b"], "exp": 5, "f": true, "d": 0.5,
               "o": {"k": 1}, "n": [[1], {"z": 2}]})
    );
}

#[test]
fn doubles_are_written_exactly() {
    let payload = json!({"whole": 1.0, "big": 18446744073709551615u64, "huge": 1e300, "half": 0.5});
    let claims = from_jwt_payload(payload.as_object().unwrap());
    assert!(claims.iter().all(|c| c.value_type == DOUBLE), "{claims:?}");
    let out = serde_json::to_string(&to_dictionary(&claims)).unwrap();
    assert_eq!(
        out,
        r#"{"whole":1,"big":1.8446744073709552e+19,"huge":1e+300,"half":0.5}"#
    );
}
