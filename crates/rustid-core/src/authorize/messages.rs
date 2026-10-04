//! Messages the server hands to the UI through a URL parameter, sealed with
//! the data protection ring as the protected data message store seals
//! them. Nothing is stored server side: the id is the sealed message.

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::data_protection::DataProtector;

/// Purpose strings, so a message of one kind can't be read as another.
pub const ERROR_MESSAGE_PURPOSE: &str = "rustid.messages.error";

/// The error message, with its PascalCase JSON names.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorMessage {
    pub error: String,
    pub error_description: Option<String>,
    pub display_mode: Option<String>,
    pub ui_locales: Option<String>,
    pub request_id: Option<String>,
    pub activity_id: Option<String>,
    /// Never set by the authorize endpoint (the redirect URI may be the
    /// cause of the error), kept for the UI contract.
    pub redirect_uri: Option<String>,
    pub response_mode: Option<String>,
    pub client_id: Option<String>,
}

/// A stored message: the data and when it was created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message<T> {
    pub data: T,
    pub created: DateTime<Utc>,
}

/// Seals a message; the result is URL-safe.
pub fn write<T: Serialize>(
    protector: &DataProtector,
    purpose: &str,
    data: T,
    now: DateTime<Utc>,
) -> String {
    let json =
        serde_json::to_vec(&Message { data, created: now }).expect("messages serialize to JSON");
    protector.protect(purpose, &json)
}

/// Opens a sealed message; `None` for anything that isn't one of ours.
pub fn read<T: DeserializeOwned>(
    protector: &DataProtector,
    purpose: &str,
    id: &str,
) -> Option<Message<T>> {
    let json = protector.unprotect(purpose, id).ok()?;
    serde_json::from_slice(&json).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protector() -> DataProtector {
        DataProtector::new([("k", [7u8; 32].as_slice())]).unwrap()
    }

    #[test]
    fn error_messages_round_trip_and_bind_their_purpose() {
        let p = protector();
        let message = ErrorMessage {
            error: "invalid_request".into(),
            client_id: Some("web".into()),
            ..Default::default()
        };
        let now = DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let id = write(&p, ERROR_MESSAGE_PURPOSE, message.clone(), now);
        assert!(
            id.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        );
        let read_back: Message<ErrorMessage> = read(&p, ERROR_MESSAGE_PURPOSE, &id).unwrap();
        assert_eq!(
            read_back,
            Message {
                data: message,
                created: now
            }
        );
        assert!(read::<ErrorMessage>(&p, "other", &id).is_none());
        assert!(read::<ErrorMessage>(&p, ERROR_MESSAGE_PURPOSE, "garbage").is_none());
    }

    #[test]
    fn error_messages_use_pascal_case_json_names() {
        let json = serde_json::to_value(ErrorMessage {
            error: "e".into(),
            ..Default::default()
        })
        .unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "activityId",
                "clientId",
                "displayMode",
                "error",
                "errorDescription",
                "redirectUri",
                "requestId",
                "responseMode",
                "uiLocales"
            ]
        );
    }
}
