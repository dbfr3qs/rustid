use std::collections::BTreeMap;

use rustid_testkit::recorded::{Body, Recorded};
use rustid_testkit::snapshot::{Snapshot, Step};
use serde_json::json;

fn snapshot(status: u16) -> Snapshot {
    Snapshot {
        scenario: "health".into(),
        steps: vec![Step {
            name: "get_health".into(),
            recorded: Recorded {
                status,
                headers: BTreeMap::new(),
                set_cookies: Vec::new(),
                body: Body::Json(json!({ "status": "ok" })),
            },
        }],
    }
}

#[test]
fn write_then_read_round_trips() {
    let dir = tempfile::tempdir().unwrap();
    snapshot(200).write(dir.path()).unwrap();
    assert!(Snapshot::path(dir.path(), "health").ends_with("health.json"));
    let read = Snapshot::read(dir.path(), "health").unwrap();
    assert_eq!(read, snapshot(200));
}

#[test]
fn read_of_missing_snapshot_names_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let err = Snapshot::read(dir.path(), "nope").unwrap_err();
    assert!(err.to_string().contains("nope.json"), "message was: {err}");
}

#[test]
fn compare_equal_snapshots_yields_nothing() {
    assert!(Snapshot::compare(&snapshot(200), &snapshot(200)).is_empty());
}

#[test]
fn compare_reports_status_difference_under_step_name() {
    let diffs = Snapshot::compare(&snapshot(200), &snapshot(500));
    assert_eq!(diffs.len(), 1);
    assert_eq!(diffs[0].step, "get_health");
    assert_eq!(diffs[0].differences[0].path, "/status");
}

#[test]
fn compare_reports_missing_and_extra_steps() {
    let mut fewer = snapshot(200);
    fewer.steps.clear();
    let diffs = Snapshot::compare(&snapshot(200), &fewer);
    assert_eq!(diffs[0].step, "get_health");
    assert_eq!(diffs[0].differences[0].path, "/");
    assert!(diffs[0].differences[0].actual.is_none());

    let diffs = Snapshot::compare(&fewer, &snapshot(200));
    assert_eq!(diffs[0].step, "get_health");
    assert!(diffs[0].differences[0].expected.is_none());
}
