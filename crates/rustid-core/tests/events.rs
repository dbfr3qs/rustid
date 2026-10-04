mod support;

use std::sync::Arc;

use chrono::{TimeZone, Utc};
use rustid_core::events::{Event, EventService, EventType, RequestInfo, obfuscate};
use rustid_core::options::EventsOptions;
use serde_json::json;
use support::RecordingSink;

fn at() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 9, 29, 12, 0, 0).unwrap()
}

#[test]
fn only_enabled_event_types_are_raised() {
    let sink = Arc::new(RecordingSink::default());
    let options = EventsOptions {
        raise_failure_events: true,
        raise_error_events: true,
        ..Default::default()
    };
    let service = EventService::new(options, sink.clone());
    let info = RequestInfo::default();
    service.raise(
        &info,
        at(),
        Event::client_authentication_success("c", "SharedSecret"),
    );
    service.raise(
        &info,
        at(),
        Event::client_authentication_failure("c", "Unknown client"),
    );
    service.raise(&info, at(), Event::unhandled_exception("boom"));
    assert_eq!(
        sink.names(),
        ["Client Authentication Failure", "Unhandled Exception"]
    );
    assert!(
        !EventService::default().can_raise(EventType::Error),
        "all off by default"
    );
}

#[test]
fn raised_events_carry_the_request_time_and_process() {
    let sink = Arc::new(RecordingSink::default());
    let service = EventService::new(
        EventsOptions {
            raise_success_events: true,
            ..Default::default()
        },
        sink.clone(),
    );
    let info = RequestInfo {
        activity_id: Some("00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01".into()),
        local_ip_address: Some("127.0.0.1:443".into()),
        remote_ip_address: Some("10.0.0.7:50000".into()),
    };
    service.raise(
        &info,
        at(),
        Event::api_authentication_success("api", "SharedSecret"),
    );
    let event = sink.take().remove(0);
    assert_eq!(event.process_id, std::process::id());
    assert_eq!(
        serde_json::to_value(&event).unwrap(),
        json!({
            "Category": "Authentication",
            "Name": "API Authentication Success",
            "EventType": "Success",
            "Id": 1020,
            "ActivityId": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
            "TimeStamp": "2026-09-29T12:00:00Z",
            "ProcessId": std::process::id(),
            "LocalIpAddress": "127.0.0.1:443",
            "RemoteIpAddress": "10.0.0.7:50000",
            "ApiName": "api",
            "AuthenticationMethod": "SharedSecret",
        })
    );
}

#[test]
fn event_ids_categories_and_messages_are_fixed() {
    let cases = [
        (
            Event::client_authentication_failure("c", "m"),
            1011,
            "Authentication",
            EventType::Failure,
        ),
        (
            Event::api_authentication_failure("a", "m"),
            1021,
            "Authentication",
            EventType::Failure,
        ),
        (
            Event::token_revoked_success("c", None, Some("access_token"), "abcdefgh"),
            2010,
            "Token",
            EventType::Success,
        ),
        (
            Event::unhandled_exception("m"),
            3000,
            "Error",
            EventType::Error,
        ),
        (
            Event::invalid_client_configuration("c", None, "m"),
            3001,
            "Error",
            EventType::Error,
        ),
    ];
    for (event, id, category, event_type) in cases {
        assert_eq!(
            (event.id, event.category, event.event_type),
            (id, category, event_type),
            "{}",
            event.name
        );
    }
    let value =
        serde_json::to_value(Event::invalid_client_configuration("c", None, "bad")).unwrap();
    assert_eq!(value["ClientName"], "unknown name");
    assert_eq!(value["Message"], "bad");
    let revoked =
        serde_json::to_value(Event::token_revoked_success("c", None, None, "abcdefgh")).unwrap();
    assert_eq!(revoked["Token"], "****efgh");
    assert!(revoked.get("TokenType").is_none() && revoked.get("ClientName").is_none());
}

#[test]
fn obfuscation_keeps_the_last_four_characters() {
    assert_eq!(obfuscate("abcdefgh"), "****efgh");
    assert_eq!(obfuscate("abcd"), "********");
    assert_eq!(obfuscate(""), "********");
    assert_eq!(obfuscate("ééééé"), "****éééé");
}
