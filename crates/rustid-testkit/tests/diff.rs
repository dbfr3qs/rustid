use rustid_testkit::diff::{Difference, json_diff};
use serde_json::json;

#[test]
fn equal_values_have_no_differences() {
    assert!(
        json_diff(
            &json!({ "a": [1, { "b": "c" }] }),
            &json!({ "a": [1, { "b": "c" }] })
        )
        .is_empty()
    );
}

#[test]
fn reports_changed_scalar_with_json_pointer_path() {
    let diffs = json_diff(&json!({ "a": { "b": 1 } }), &json!({ "a": { "b": 2 } }));
    assert_eq!(
        diffs,
        vec![Difference {
            path: "/a/b".into(),
            expected: Some(json!(1)),
            actual: Some(json!(2))
        }]
    );
}

#[test]
fn reports_missing_and_extra_keys() {
    let diffs = json_diff(&json!({ "a": 1, "b": 2 }), &json!({ "b": 2, "c": 3 }));
    assert_eq!(
        diffs,
        vec![
            Difference {
                path: "/a".into(),
                expected: Some(json!(1)),
                actual: None
            },
            Difference {
                path: "/c".into(),
                expected: None,
                actual: Some(json!(3))
            },
        ]
    );
}

#[test]
fn reports_array_length_and_element_differences() {
    let diffs = json_diff(&json!([1, 2, 3]), &json!([1, 9]));
    assert_eq!(
        diffs,
        vec![
            Difference {
                path: "/1".into(),
                expected: Some(json!(2)),
                actual: Some(json!(9))
            },
            Difference {
                path: "/2".into(),
                expected: Some(json!(3)),
                actual: None
            },
        ]
    );
}

#[test]
fn type_change_is_a_single_difference_at_that_path() {
    let diffs = json_diff(&json!({ "a": { "b": 1 } }), &json!({ "a": "text" }));
    assert_eq!(
        diffs,
        vec![Difference {
            path: "/a".into(),
            expected: Some(json!({ "b": 1 })),
            actual: Some(json!("text"))
        }]
    );
}
