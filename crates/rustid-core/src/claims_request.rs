//! The `claims` request parameter (OpenID Connect Core 1.0 §5.5): the
//! claims a client asks for in userinfo and in the id token. Each is a
//! plain request: `essential`, `value` and `values` don't change what's
//! issued, and only the claim types of identity resources the client may
//! have are kept.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::resources::IdentityResource;

/// The claim types asked for, in request order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestedClaims {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub userinfo: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub id_token: Vec<String>,
}

/// A member's claim names; `None` when it isn't an object of null or
/// object values.
fn member(document: &Map<String, Value>, name: &str) -> Option<Vec<String>> {
    let Some(value) = document.get(name) else {
        return Some(Vec::new());
    };
    let requests = value.as_object()?;
    requests
        .iter()
        .map(|(claim, request)| (request.is_null() || request.is_object()).then(|| claim.clone()))
        .collect()
}

impl RequestedClaims {
    /// The parameter's value; `None` when it isn't a JSON object whose
    /// `userinfo` and `id_token` members are objects of claim requests.
    /// Other members are ignored.
    pub fn parse(value: &str) -> Option<RequestedClaims> {
        let document = serde_json::from_str::<Value>(value).ok()?;
        let document = document.as_object()?;
        Some(RequestedClaims {
            userinfo: member(document, "userinfo")?,
            id_token: member(document, "id_token")?,
        })
    }

    /// Whether nothing is asked for.
    pub fn is_empty(&self) -> bool {
        self.userinfo.is_empty() && self.id_token.is_empty()
    }

    /// Only the claim types the identity resources carry.
    pub fn limited_to(&self, resources: &[IdentityResource]) -> RequestedClaims {
        let allowed = |claim: &&String| {
            resources
                .iter()
                .any(|r| r.user_claims.iter().any(|c| c == *claim))
        };
        RequestedClaims {
            userinfo: self.userinfo.iter().filter(allowed).cloned().collect(),
            id_token: self.id_token.iter().filter(allowed).cloned().collect(),
        }
    }
}
