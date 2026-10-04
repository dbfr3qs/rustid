use std::path::Path;

use rustid_core::resources::{Resources, ResourcesError};

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

#[test]
fn loads_the_shared_fixture() {
    let r = Resources::load(&fixture("resources.json")).unwrap();
    let names: Vec<&str> = r
        .identity_resources
        .iter()
        .map(|i| i.name.as_str())
        .collect();
    assert_eq!(names, ["openid", "profile", "custom_identity"]);
    assert!(r.identity_resources[0].required);
    assert!(r.identity_resources[1].show_in_discovery_document);
    assert_eq!(r.api_scopes[0].name, "api1");
    assert_eq!(r.api_resources[0].scopes, ["api1"]);
    assert_eq!(r.api_resources[0].user_claims, ["role", "name"]);
}

#[test]
fn enabled_filters_disabled_entries() {
    let r: Resources = serde_json::from_str(
        r#"{ "apiScopes": [ { "name": "on" }, { "name": "off", "enabled": false } ] }"#,
    )
    .unwrap();
    let names: Vec<String> = r.enabled().api_scopes.into_iter().map(|s| s.name).collect();
    assert_eq!(names, ["on"]);
}

#[test]
fn missing_file_names_the_path() {
    let err = Resources::load(Path::new("/nonexistent/resources.json")).unwrap_err();
    assert!(matches!(err, ResourcesError::Read { .. }));
    assert!(
        err.to_string().contains("/nonexistent/resources.json"),
        "{err}"
    );
}

#[test]
fn malformed_file_names_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(&path, "{ not json").unwrap();
    let err = Resources::load(&path).unwrap_err();
    assert!(matches!(err, ResourcesError::Parse { .. }));
    assert!(err.to_string().contains("bad.json"), "{err}");
}

#[test]
fn duplicate_names_within_a_list_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.json");
    for (list, kind) in [
        ("identityResources", "identity resource"),
        ("apiScopes", "API scope"),
        ("apiResources", "API resource"),
    ] {
        std::fs::write(
            &path,
            format!(r#"{{"{list}": [{{"name": "x"}}, {{"name": "x"}}]}}"#),
        )
        .unwrap();
        let err = Resources::load(&path).unwrap_err();
        assert!(
            matches!(&err, ResourcesError::Duplicate { kind: k, name, .. } if *k == kind && name == "x"),
            "{list}: {err}"
        );
    }
    std::fs::write(
        &path,
        r#"{"identityResources": [{"name": "x"}], "apiResources": [{"name": "x"}]}"#,
    )
    .unwrap();
    assert!(
        Resources::load(&path).is_ok(),
        "API resource names may repeat identity resource names"
    );
}

#[test]
fn identity_and_api_scopes_sharing_a_name_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resources.json");
    std::fs::write(
        &path,
        r#"{"identityResources": [{"name": "openid"}, {"name": "foo"}, {"name": "bar"}],
            "apiScopes": [{"name": "bar"}, {"name": "foo"}]}"#,
    )
    .unwrap();
    let err = Resources::load(&path).unwrap_err();
    assert!(
        matches!(&err, ResourcesError::Overlap { names, .. } if names == "foo, bar"),
        "{err}"
    );
}
