//! Scope parsing and resource validation.

use crate::clients::Client;
use crate::resources::{ApiResource, ApiScope, IdentityResource, Resources};

pub const OFFLINE_ACCESS: &str = "offline_access";

/// Trimmed, split on spaces, empty entries removed,
/// de-duplicated and sorted. `None` when nothing remains.
///
/// This sorts ordinally, which agrees with culture-aware sorting for
/// the lower-case ASCII scope names the fixtures use.
pub fn parse_scopes_string(scopes: &str) -> Option<Vec<String>> {
    let mut parsed: Vec<String> = Vec::new();
    for scope in scopes.trim().split(' ').filter(|s| !s.is_empty()) {
        if !parsed.iter().any(|p| p == scope) {
            parsed.push(scope.to_owned());
        }
    }
    parsed.sort();
    (!parsed.is_empty()).then_some(parsed)
}

/// The outcome of a successful validation: the resources the scopes grant,
/// in the order they accumulate.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ValidatedResources {
    pub identity_resources: Vec<IdentityResource>,
    pub api_scopes: Vec<ApiScope>,
    pub api_resources: Vec<ApiResource>,
    pub offline_access: bool,
    /// The granted scopes in request (sorted) order.
    pub scopes: Vec<String>,
}

impl ValidatedResources {
    /// The requested scopes whose identity
    /// resource or API scope is required.
    pub fn required_scope_values(&self) -> Vec<String> {
        self.scopes
            .iter()
            .filter(|s| {
                self.identity_resources
                    .iter()
                    .any(|r| &r.name == *s && r.required)
                    || self.api_scopes.iter().any(|a| &a.name == *s && a.required)
            })
            .cloned()
            .collect()
    }

    /// Only the given scope values, in
    /// the original order, with the resources they need.
    pub fn filter(&self, scope_values: &[String]) -> ValidatedResources {
        let keep = |name: &str| scope_values.iter().any(|v| v == name);
        let api_scopes: Vec<ApiScope> = self
            .api_scopes
            .iter()
            .filter(|a| keep(&a.name))
            .cloned()
            .collect();
        ValidatedResources {
            identity_resources: self
                .identity_resources
                .iter()
                .filter(|r| keep(&r.name))
                .cloned()
                .collect(),
            api_resources: self
                .api_resources
                .iter()
                .filter(|r| {
                    r.scopes
                        .iter()
                        .any(|s| api_scopes.iter().any(|a| &a.name == s))
                })
                .cloned()
                .collect(),
            api_scopes,
            offline_access: self.offline_access && keep(OFFLINE_ACCESS),
            scopes: self.scopes.iter().filter(|s| keep(s)).cloned().collect(),
        }
    }

    /// With an indicator, only the API resource
    /// it names, the API scopes of that resource, and the requested scopes
    /// among them (plus `offline_access`); identity resources stay, for the
    /// id token. Without one, the API resources that don't insist on being
    /// named.
    pub fn filter_by_resource_indicator(&self, indicator: Option<&str>) -> ValidatedResources {
        let Some(indicator) = indicator.filter(|i| !i.trim().is_empty()) else {
            return ValidatedResources {
                api_resources: self
                    .api_resources
                    .iter()
                    .filter(|a| !a.require_resource_indicator)
                    .cloned()
                    .collect(),
                ..self.clone()
            };
        };
        let api_resources: Vec<ApiResource> = self
            .api_resources
            .iter()
            .filter(|a| a.name == indicator)
            .cloned()
            .collect();
        let keep = |name: &str| {
            api_resources
                .iter()
                .any(|a| a.scopes.iter().any(|s| s == name))
        };
        let mut scopes: Vec<String> = self.scopes.iter().filter(|s| keep(s)).cloned().collect();
        if self.offline_access && !scopes.iter().any(|s| s == OFFLINE_ACCESS) {
            scopes.push(OFFLINE_ACCESS.to_owned());
        }
        ValidatedResources {
            identity_resources: self.identity_resources.clone(),
            api_scopes: self
                .api_scopes
                .iter()
                .filter(|a| keep(&a.name))
                .cloned()
                .collect(),
            api_resources,
            offline_access: self.offline_access,
            scopes,
        }
    }

    /// Distinct API resource names: the access token audiences.
    pub fn audiences(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for api in &self.api_resources {
            if !out.contains(&api.name) {
                out.push(api.name.clone());
            }
        }
        out
    }

    /// The algorithms every constraining API
    /// resource allows. `Ok(empty)` when none constrains; `Err` when their
    /// lists have nothing in common.
    pub fn allowed_signing_algorithms(&self) -> Result<Vec<String>, NoCommonSigningAlgorithm> {
        let mut constrained = self
            .api_resources
            .iter()
            .filter(|a| !a.allowed_access_token_signing_algorithms.is_empty());
        let Some(first) = constrained.next() else {
            return Ok(Vec::new());
        };
        let mut allowed = first.allowed_access_token_signing_algorithms.clone();
        for api in constrained {
            allowed.retain(|alg| api.allowed_access_token_signing_algorithms.contains(alg));
        }
        if allowed.is_empty() {
            Err(NoCommonSigningAlgorithm)
        } else {
            Ok(allowed)
        }
    }
}

/// The requested APIs restrict access token signing algorithms and no
/// algorithm is allowed by all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the requested APIs allow no common access token signing algorithm")]
pub struct NoCommonSigningAlgorithm;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceValidationError {
    /// One or more resource indicators name no enabled API resource that
    /// covers a requested scope.
    InvalidResourceIndicator(Vec<String>),
    /// One or more scopes are unknown or not allowed for the client.
    InvalidScope(Vec<String>),
}

/// Validate requested resources. `resources` must already be filtered
/// to enabled entries.
pub fn validate_requested_resources(
    client: &Client,
    resources: &Resources,
    requested: &[String],
    resource_indicators: &[String],
) -> Result<ValidatedResources, ResourceValidationError> {
    // Resources whose scopes were requested, minus APIs that insist on an
    // explicit resource indicator and weren't named by one.
    let apis: Vec<&ApiResource> = resources
        .api_resources
        .iter()
        .filter(|api| api.scopes.iter().any(|s| requested.contains(s)))
        .filter(|api| !api.require_resource_indicator || resource_indicators.contains(&api.name))
        .collect();
    let unmatched: Vec<String> = resource_indicators
        .iter()
        .filter(|r| !apis.iter().any(|api| &api.name == *r))
        .cloned()
        .collect();
    if !unmatched.is_empty() {
        return Err(ResourceValidationError::InvalidResourceIndicator(unmatched));
    }

    let mut result = ValidatedResources::default();
    let mut invalid = Vec::new();
    for scope in requested {
        if scope == OFFLINE_ACCESS {
            if client.allow_offline_access {
                result.offline_access = true;
                result.scopes.push(scope.clone());
            } else {
                invalid.push(scope.clone());
            }
        } else if let Some(identity) = resources
            .identity_resources
            .iter()
            .find(|r| &r.name == scope)
        {
            if client.allowed_scopes.contains(scope) {
                result.scopes.push(scope.clone());
                result.identity_resources.push(identity.clone());
            } else {
                invalid.push(scope.clone());
            }
        } else if let Some(api_scope) = resources.api_scopes.iter().find(|s| &s.name == scope) {
            if client.allowed_scopes.contains(scope) {
                result.scopes.push(scope.clone());
                result.api_scopes.push(api_scope.clone());
                for api in apis.iter().filter(|a| a.scopes.contains(scope)) {
                    if !result.api_resources.iter().any(|r| r.name == api.name) {
                        result.api_resources.push((*api).clone());
                    }
                }
            } else {
                invalid.push(scope.clone());
            }
        } else {
            invalid.push(scope.clone());
        }
    }
    if invalid.is_empty() {
        Ok(result)
    } else {
        Err(ResourceValidationError::InvalidScope(invalid))
    }
}
