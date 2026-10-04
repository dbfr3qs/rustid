//! The admin model: UUIDv7 ids, errors and paging.

use rustid_core::admin::query::{Range, paginate};
use rustid_core::admin::{AdminError, EntityId};

#[test]
fn ids_are_uuid_v7_and_round_trip() {
    let a = EntityId::new_v7();
    let text = a.to_string();
    assert_eq!(text.len(), 36);
    assert_eq!(&text[14..15], "7", "version 7: {text}");
    assert!(
        matches!(&text[19..20], "8" | "9" | "a" | "b"),
        "variant: {text}"
    );
    assert_eq!(text.parse::<EntityId>().unwrap(), a);
    assert!("not-an-id".parse::<EntityId>().is_err());
    assert!(
        "0192e1f2-0000-7000-8000-00000000000g"
            .parse::<EntityId>()
            .is_err()
    );
    std::thread::sleep(std::time::Duration::from_millis(2));
    let b = EntityId::new_v7();
    assert!(b.to_string() > a.to_string(), "time-ordered");
}

#[test]
fn errors_carry_stable_codes_and_messages() {
    let e = AdminError::already_exists("api_scope", "x");
    assert_eq!(
        (e.code, e.message.as_str()),
        ("already_exists", "api_scope 'x' already exists.")
    );
    let e = AdminError::not_found("identity_resource", "abc");
    assert_eq!(
        (e.code, e.message.as_str()),
        ("not_found", "identity_resource 'abc' was not found.")
    );
    let e = AdminError::version_conflict();
    assert_eq!(e.code, "version_conflict");
    assert_eq!(
        e.message,
        "The item has been modified by another operation. Please refresh and try again."
    );
    let e = AdminError::required("Name");
    assert_eq!(
        (e.code, e.message.as_str()),
        ("required", "A value is required.")
    );
    assert_eq!(e.property_names, ["Name"]);
    let e = AdminError::invalid_value("UserClaims", "bad");
    assert_eq!(
        (e.code, e.property_names.as_slice()),
        ("invalid_value", ["UserClaims".to_owned()].as_slice())
    );
    assert_eq!(AdminError::validation_failed("x").code, "validation_failed");
}

#[test]
fn pages_offsets_and_tokens() {
    let items: Vec<u32> = (0..7).collect();
    let page = |n| paginate(items.clone(), &Range::Page { page: n, size: 3 }).unwrap();
    let first = page(1);
    assert_eq!(first.items, [0, 1, 2]);
    assert_eq!(
        (first.total_count, first.total_pages, first.has_more_data),
        (7, 3, true)
    );
    assert_eq!(page(3).items, [6]);
    assert!(!page(3).has_more_data);
    assert!(page(4).items.is_empty());
    let offset = paginate(items.clone(), &Range::Offset { skip: 5, take: 3 }).unwrap();
    assert_eq!(offset.items, [5, 6]);

    // Following continuation tokens gives the same pages.
    let mut token = None;
    let mut seen = Vec::new();
    loop {
        let r = paginate(
            items.clone(),
            &Range::Token {
                token: token.clone(),
                size: 3,
            },
        )
        .unwrap();
        seen.extend(r.items.clone());
        match r.next_token {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    assert_eq!(seen, items);

    for bad in [
        Range::Page { page: 1, size: 0 },
        Range::Page {
            page: 1,
            size: 1001,
        },
        Range::Page { page: 0, size: 3 },
        Range::Token {
            token: Some("!!".into()),
            size: 3,
        },
    ] {
        assert_eq!(
            paginate(items.clone(), &bad).unwrap_err().code,
            "invalid_value",
            "{bad:?}"
        );
    }
}

#[test]
fn secrets_hash_and_imported_ones_get_stable_ids() {
    use rustid_core::admin::secrets::{HashAlgorithm, derived_secret_id, hash_secret};
    assert_eq!(
        hash_secret("secret", HashAlgorithm::Sha256),
        "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="
    );
    let sha512 = hash_secret("secret", HashAlgorithm::Sha512);
    assert_eq!(sha512.len(), 88, "base64 of 64 bytes");
    assert_ne!(sha512, hash_secret("secret", HashAlgorithm::Sha256));
    let a = derived_secret_id("SharedSecret", "abc");
    assert_eq!(a, derived_secret_id("SharedSecret", "abc"), "stable");
    assert_ne!(a, derived_secret_id("SharedSecret", "abd"));
    assert_ne!(a, derived_secret_id("JWK", "abc"));
    assert_eq!(&a.to_string()[14..15], "8", "version 8");
}

#[test]
fn stored_secret_expirations_read_in_both_forms() {
    use rustid_core::admin::secrets::configuration;
    let rfc =
        configuration(&serde_json::json!({ "value": "v", "expiration": "2030-01-01T00:00:00Z" }));
    let naive =
        configuration(&serde_json::json!({ "value": "v", "expiration": "2030-01-01T00:00:00" }));
    assert_eq!(rfc.expiration, naive.expiration);
    assert!(rfc.expiration.is_some());
    assert_eq!(rfc.secret_type, "SharedSecret");
}
