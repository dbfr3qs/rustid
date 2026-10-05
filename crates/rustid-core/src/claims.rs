//! Conversions between claims and JSON: reading a validated JWT payload
//! as claims, and claims as a JSON object.

use serde_json::{Map, Value};

use crate::clients::CLAIM_VALUE_TYPE_STRING;
use crate::tokens::{
    CLAIM_VALUE_BOOLEAN, CLAIM_VALUE_DOUBLE, CLAIM_VALUE_INTEGER, CLAIM_VALUE_INTEGER32,
    CLAIM_VALUE_INTEGER64, CLAIM_VALUE_JSON, Claim,
};

/// The value type JWT handler gives nested objects and arrays.
pub const CLAIM_VALUE_JSON_UPPER: &str = "JSON";

/// Claims from a JWT payload: arrays become one claim per element; numbers,
/// booleans and nested JSON keep a typed value type.
pub fn from_jwt_payload(payload: &Map<String, Value>) -> Vec<Claim> {
    let mut claims = Vec::new();
    for (name, value) in payload {
        match value {
            Value::Array(items) => claims.extend(items.iter().map(|item| scalar_claim(name, item))),
            other => claims.push(scalar_claim(name, other)),
        }
    }
    claims
}

fn scalar_claim(name: &str, value: &Value) -> Claim {
    let (text, value_type) = match value {
        Value::String(s) => (s.clone(), CLAIM_VALUE_TYPE_STRING),
        Value::Bool(true) => ("true".to_owned(), CLAIM_VALUE_BOOLEAN),
        Value::Bool(false) => ("false".to_owned(), CLAIM_VALUE_BOOLEAN),
        Value::Number(n) if n.is_i64() => (n.to_string(), CLAIM_VALUE_INTEGER64),
        // Beyond i64 or fractional: a double.
        Value::Number(n) => (
            n.as_f64().map(|f| f.to_string()).unwrap_or_default(),
            CLAIM_VALUE_DOUBLE,
        ),
        Value::Null => (String::new(), CLAIM_VALUE_TYPE_STRING),
        nested => (nested.to_string(), CLAIM_VALUE_JSON_UPPER),
    };
    Claim {
        claim_type: name.to_owned(),
        value: text,
        value_type: value_type.to_owned(),
    }
}

/// Distinct claims keyed by type in first-seen order;
/// a repeated type becomes an array of its values. Each value is converted
/// by its value type, falling back to the string when it does not parse.
pub fn to_dictionary(claims: &[Claim]) -> Map<String, Value> {
    let mut out = Map::new();
    let mut seen: Vec<&Claim> = Vec::new();
    // Types whose value is a list this function built, as opposed to a JSON
    // array value, which is wrapped rather than extended.
    let mut grouped: Vec<&str> = Vec::new();
    for claim in claims {
        if seen.contains(&claim) {
            continue;
        }
        seen.push(claim);
        let value = value_of(claim);
        match out.get_mut(&claim.claim_type) {
            None => {
                out.insert(claim.claim_type.clone(), value);
            }
            Some(Value::Array(list)) if grouped.contains(&claim.claim_type.as_str()) => {
                list.push(value)
            }
            Some(existing) => {
                let first = existing.take();
                *existing = Value::Array(vec![first, value]);
                grouped.push(&claim.claim_type);
            }
        }
    }
    out
}

/// A claim's value as JSON, by its value type.
fn value_of(claim: &Claim) -> Value {
    let vt = claim.value_type.as_str();
    let text = claim.value.as_str();
    let parsed = if vt == CLAIM_VALUE_INTEGER || vt == CLAIM_VALUE_INTEGER32 {
        text.trim().parse::<i32>().ok().map(Value::from)
    } else if vt == CLAIM_VALUE_INTEGER64 {
        text.trim().parse::<i64>().ok().map(Value::from)
    } else if vt == CLAIM_VALUE_DOUBLE {
        text.trim().parse::<f64>().ok().map(wire_double)
    } else if vt == CLAIM_VALUE_BOOLEAN {
        match text.trim().to_ascii_lowercase().as_str() {
            "true" => Some(Value::Bool(true)),
            "false" => Some(Value::Bool(false)),
            _ => None,
        }
    } else if vt.eq_ignore_ascii_case(CLAIM_VALUE_JSON) {
        serde_json::from_str(text).ok()
    } else {
        None
    };
    parsed.unwrap_or_else(|| Value::String(text.to_owned()))
}

/// A double as JSON on the wire: whole numbers below 10^15 have
/// no fraction or exponent, so they read back as JSON integers.
pub fn wire_double(f: f64) -> Value {
    if f.fract() == 0.0 && f.abs() < 1e15 {
        Value::from(f as i64)
    } else {
        Value::from(f)
    }
}
