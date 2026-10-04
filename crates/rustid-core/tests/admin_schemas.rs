//! Data extension schemas and extended property validation, with
//! stable messages.
//! 2.0.0-preview.2`).

use rustid_core::admin::schemas::{
    AttributeDefinition, AttributeType, ScalarDataType, SchemaConfiguration, string_properties,
    validate_extended_properties,
};
use serde_json::{Map, Value, json};

fn scalar(data_type: ScalarDataType) -> AttributeType {
    AttributeType::Scalar { data_type }
}

fn def(code: &str, attribute_type: AttributeType) -> AttributeDefinition {
    AttributeDefinition {
        code: code.into(),
        attribute_type,
        ..Default::default()
    }
}

fn schema() -> SchemaConfiguration {
    serde_json::from_value(json!({
        "schemaId": "client",
        "displayName": "Client",
        "attributeDefinitions": [
            { "code": "department", "attributeType": { "kind": "scalar", "dataType": "String" } },
            { "code": "cost_center", "attributeType": { "kind": "scalar", "dataType": "Integer" } },
            { "code": "ratio", "attributeType": { "kind": "scalar", "dataType": "Decimal" } },
            { "code": "flag", "attributeType": { "kind": "scalar", "dataType": "Boolean" } },
            { "code": "day", "attributeType": { "kind": "scalar", "dataType": "Date" } },
            { "code": "at", "attributeType": { "kind": "scalar", "dataType": "DateTime" } },
            { "code": "tags", "attributeType": { "kind": "list",
                "elementType": { "kind": "scalar", "dataType": "String" } } },
            { "code": "addr", "attributeType": { "kind": "complex", "properties": {
                "street": { "type": { "kind": "scalar", "dataType": "String" } } } } },
        ],
    }))
    .unwrap()
}

fn values(json: Value) -> Map<String, Value> {
    match json {
        Value::Object(map) => map,
        _ => panic!("an object"),
    }
}

fn errors(json: Value, schema: Option<&SchemaConfiguration>) -> Vec<String> {
    validate_extended_properties(&values(json), schema)
}

#[test]
fn values_of_the_right_type_pass() {
    let s = schema();
    assert_eq!(
        errors(
            json!({
                "department": "Eng", "cost_center": 1042, "ratio": 0.5, "flag": false,
                "day": "2026-10-01", "at": "2026-10-01T10:00:00+02:00",
                "tags": ["a", 3], "addr": { "zip": 1 },
            }),
            Some(&s)
        ),
        Vec::<String>::new(),
        "list elements and complex properties are unchecked"
    );
    assert_eq!(
        errors(json!({ "Cost_Center": 1 }), Some(&s)),
        Vec::<String>::new(),
        "codes compare case-insensitively"
    );
}

#[test]
fn mismatches_name_the_expected_type() {
    let s = schema();
    for (value, message) in [
        (
            json!({ "cost_center": "x" }),
            "Attribute 'cost_center' type mismatch: expected 'Integer'.",
        ),
        (
            json!({ "cost_center": 3.5 }),
            "Attribute 'cost_center' type mismatch: expected 'Integer'.",
        ),
        (
            json!({ "cost_center": 3_000_000_000_i64 }),
            "Attribute 'cost_center' type mismatch: expected 'Integer'.",
        ),
        (
            json!({ "department": 3 }),
            "Attribute 'department' type mismatch: expected 'String'.",
        ),
        (
            json!({ "department": null }),
            "Attribute 'department' type mismatch: expected 'String'.",
        ),
        (
            json!({ "ratio": "1" }),
            "Attribute 'ratio' type mismatch: expected 'Decimal'.",
        ),
        (
            json!({ "flag": "true" }),
            "Attribute 'flag' type mismatch: expected 'Boolean'.",
        ),
        (
            json!({ "day": "2026-10-01T00:00:00Z" }),
            "Attribute 'day' type mismatch: expected 'Date'.",
        ),
        (
            json!({ "at": "2026-10-01" }),
            "Attribute 'at' type mismatch: expected 'DateTime'.",
        ),
        (
            json!({ "tags": "a" }),
            "Attribute 'tags' type mismatch: expected 'ListAttributeType'.",
        ),
        (
            json!({ "department": ["a"] }),
            "Attribute 'department' type mismatch: expected 'String'.",
        ),
        (
            json!({ "addr": "x" }),
            "Attribute 'addr' type mismatch: expected 'ComplexAttributeType'.",
        ),
    ] {
        assert_eq!(errors(value.clone(), Some(&s)), [message], "{value}");
    }
}

#[test]
fn errors_come_in_input_order_then_missing_required() {
    let mut s = schema();
    s.attribute_definitions = vec![
        AttributeDefinition {
            is_required: true,
            ..def("a", scalar(ScalarDataType::String))
        },
        def("b", scalar(ScalarDataType::Integer)),
        AttributeDefinition {
            is_required: true,
            ..def("c", scalar(ScalarDataType::String))
        },
    ];
    assert_eq!(
        errors(json!({ "zz": "v", "b": "x", "yy": 1 }), Some(&s)),
        [
            "Attribute 'zz' is not defined in the schema.",
            "Attribute 'b' type mismatch: expected 'Integer'.",
            "Attribute 'yy' is not defined in the schema.",
            "Required attribute 'a' is missing.",
            "Required attribute 'c' is missing.",
        ]
    );
    assert_eq!(
        errors(json!({ "A": "v", "C": "w" }), Some(&s)),
        Vec::<String>::new()
    );
}

#[test]
fn no_schema_defines_nothing() {
    assert_eq!(
        errors(json!({ "department": "x" }), None),
        ["Attribute 'department' is not defined in the schema."]
    );
}

#[test]
fn codes_differing_only_in_case_are_refused() {
    assert_eq!(
        errors(
            json!({ "department": "a", "Department": "b" }),
            Some(&schema())
        ),
        ["The attributes contain more than one attribute named 'Department'."]
    );
}

#[test]
fn string_properties_are_the_string_typed_values() {
    let s = schema();
    let found = string_properties(
        &values(json!({ "department": "Eng", "cost_center": 3, "day": "2026-10-01" })),
        Some(&s),
    );
    assert_eq!(
        found.into_iter().collect::<Vec<_>>(),
        [("department".to_owned(), "Eng".to_owned())]
    );
}

#[test]
fn schemas_round_trip_through_json() {
    let s = schema();
    let json = serde_json::to_value(&s).unwrap();
    assert_eq!(json["attributeDefinitions"][0]["isRequired"], false);
    assert_eq!(json["attributeDefinitions"][0]["tags"], json!([]));
    assert_eq!(
        json["attributeDefinitions"][6]["attributeType"]["elementType"]["dataType"],
        "String"
    );
    assert_eq!(
        serde_json::from_value::<SchemaConfiguration>(json).unwrap(),
        s
    );
}

#[test]
fn schema_validation_follows_the_value_object_rules() {
    let check = |f: &dyn Fn(&mut SchemaConfiguration)| {
        let mut s = schema();
        f(&mut s);
        s.validate()
            .map(|e| (e.code, e.message, e.property_names.join(",")))
    };
    assert_eq!(check(&|_| {}), None);
    type Case<'a> = (
        &'a dyn Fn(&mut SchemaConfiguration),
        &'a str,
        &'a str,
        &'a str,
    );
    let cases: Vec<Case> = vec![
        (
            &|s| s.schema_id = " ".into(),
            "required",
            "A value is required.",
            "SchemaId",
        ),
        (
            &|s| s.schema_id = "a".repeat(51),
            "invalid_value",
            "Must not exceed 50 characters.",
            "SchemaId",
        ),
        (
            &|s| s.schema_id = "a.b".into(),
            "invalid_value",
            "Must match the required pattern.",
            "SchemaId",
        ),
        (
            &|s| s.schema_id = "-a".into(),
            "invalid_value",
            "Must match the required pattern.",
            "SchemaId",
        ),
        (
            &|s| s.attribute_definitions[0].code = "".into(),
            "required",
            "A value is required.",
            "AttributeDefinitions",
        ),
        (
            &|s| s.attribute_definitions[0].code = "9bad".into(),
            "invalid_value",
            "Must start with an ASCII letter.",
            "AttributeDefinitions",
        ),
        (
            &|s| s.attribute_definitions[0].code = "bad-dash".into(),
            "invalid_value",
            "Must only contain ASCII letters, digits, or underscores.",
            "AttributeDefinitions",
        ),
        (
            &|s| s.attribute_definitions[0].code = "bad_".into(),
            "invalid_value",
            "Must not end with an underscore.",
            "AttributeDefinitions",
        ),
        (
            &|s| s.attribute_definitions[0].code = "a".repeat(101),
            "invalid_value",
            "Must not exceed 100 characters.",
            "AttributeDefinitions",
        ),
        (
            &|s| s.attribute_definitions[0].description = Some("d".repeat(201)),
            "invalid_value",
            "Must not exceed 200 characters.",
            "AttributeDefinitions",
        ),
        (
            &|s| {
                s.attribute_definitions[0].attribute_type = AttributeType::List {
                    element_type: Box::new(AttributeType::List {
                        element_type: Box::new(scalar(ScalarDataType::String)),
                    }),
                }
            },
            "invalid_value",
            "List types cannot be nested inside another list type.",
            "AttributeDefinitions",
        ),
        (
            &|s| {
                s.attribute_definitions[0].attribute_type = AttributeType::Complex {
                    properties: Default::default(),
                }
            },
            "invalid_value",
            "Properties must contain at least one entry.",
            "AttributeDefinitions",
        ),
    ];
    for (change, code, message, property) in cases {
        assert_eq!(
            check(change),
            Some((code, message.to_owned(), property.to_owned())),
            "{message}"
        );
    }
    for ok in ["idp:my-oidc", "a_b", "1abc", "Client", "a:"] {
        assert_eq!(check(&|s| s.schema_id = ok.into()), None, "{ok}");
    }
}
