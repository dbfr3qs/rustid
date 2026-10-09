//! The `claims` request parameter (OpenID Connect Core 1.0 §5.5): the
//! claims a client asks for in userinfo and in the id token. Each is a
//! plain request: `essential`, `value` and `values` don't change what's
//! issued, and only the claim types of identity resources the client may
//! have are kept.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::clients::Client;
use crate::resources::IdentityResource;
use crate::scopes::ValidatedResources;
use crate::tokens::Claim;

/// The access token claim carrying the claim types asked for in userinfo,
/// one claim per type.
pub const USERINFO_CLAIMS: &str = "userinfo_claims";

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

    /// Only the claim types of identity resources the client is allowed
    /// (`resources` being the enabled ones).
    pub fn allowed(&self, client: &Client, resources: &[IdentityResource]) -> RequestedClaims {
        let allowed: Vec<IdentityResource> = resources
            .iter()
            .filter(|r| client.allowed_scopes.contains(&r.name))
            .cloned()
            .collect();
        self.limited_to(&allowed)
    }

    /// What the grant may carry: when the client requires consent, or the
    /// consent page was shown anyway (`prompt=consent`), only the claim
    /// types of the identity resources granted.
    pub fn granted(
        &self,
        client: &Client,
        resources: &ValidatedResources,
        consent_shown: bool,
    ) -> RequestedClaims {
        if client.require_consent || consent_shown {
            self.limited_to(&resources.identity_resources)
        } else {
            self.clone()
        }
    }

    /// The access token claims recording the userinfo request.
    pub fn userinfo_claims(&self) -> impl Iterator<Item = Claim> + '_ {
        self.userinfo
            .iter()
            .map(|name| Claim::string(USERINFO_CLAIMS, name))
    }
}
