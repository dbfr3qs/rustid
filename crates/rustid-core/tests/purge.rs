//! The storage purge: expired
//! grants, device codes, replay and throttling entries, in batches.

use chrono::{Duration, TimeZone, Utc};
use rustid_core::clients::Clients;
use rustid_core::grants::PersistedGrant;
use rustid_core::purge::{PurgeSettings, Purged, run};
use rustid_core::resources::Resources;

fn grant(key: &str, expiration: chrono::DateTime<Utc>) -> PersistedGrant {
    PersistedGrant {
        key: key.into(),
        grant_type: "reference_token".into(),
        client_id: "c".into(),
        subject_id: None,
        session_id: None,
        description: None,
        creation_time: expiration - Duration::hours(1),
        expiration: Some(expiration),
        consumed_time: None,
        data: "{}".into(),
    }
}

#[tokio::test]
async fn one_run_purges_every_store_across_batches() {
    let stores = rustid_store_memory::stores(Clients::default(), Resources::default());
    let now = Utc.timestamp_opt(1_700_000_000, 0).unwrap();
    for i in 0..5 {
        stores
            .grants
            .store(grant(&format!("old-{i}"), now - Duration::seconds(1)))
            .await
            .unwrap();
    }
    stores
        .grants
        .store(grant("live", now + Duration::hours(1)))
        .await
        .unwrap();
    for code in ["D1", "D2"] {
        stores
            .device_flow
            .store_device_authorization(
                code,
                &format!("U{code}"),
                "c",
                now - Duration::hours(1),
                now - Duration::seconds(1),
                "{}",
            )
            .await
            .unwrap();
    }
    let then = now.timestamp() - 100;
    stores
        .replay
        .add_if_absent("p", "old", then + 1, then)
        .await
        .unwrap();
    stores
        .device_throttling
        .should_slow_down("old", 5, 1, now - Duration::seconds(100))
        .await
        .unwrap();

    let purged = run(
        &stores,
        &PurgeSettings {
            batch: 2,
            remove_consumed: false,
            consumed_delay: 0,
        },
        now,
    )
    .await
    .unwrap();
    assert_eq!(
        purged,
        Purged {
            grants: 5,
            device_codes: 2,
            replay: 1,
            throttling: 1,
        }
    );
    assert!(stores.grants.get("live").await.unwrap().is_some());
}
