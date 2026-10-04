//! The first problem,
//! in a fixed order with fixed words.

use crate::model::{Binding, ServiceProvider};

pub fn validate_service_provider(sp: &ServiceProvider) -> Result<(), String> {
    if sp.entity_id.trim().is_empty() {
        return Err("EntityId is required".into());
    }
    if sp.assertion_consumer_service_urls.is_empty() {
        return Err("at least one Assertion Consumer Service URL is required".into());
    }
    if let Some(acs) = sp
        .assertion_consumer_service_urls
        .iter()
        .find(|acs| acs.binding != Binding::HttpPost)
    {
        return Err(format!(
            "Assertion Consumer Service at index {} uses an unsupported binding '{}'. Only HTTP-POST is supported for SAML Response delivery.",
            acs.index,
            acs.binding.name()
        ));
    }
    if sp.allowed_scopes.is_empty() {
        return Err("at least one allowed scope is required".into());
    }
    if sp.assertion_lifetime.is_some_and(|t| t.0 <= 0) {
        return Err("AssertionLifetime must be positive".into());
    }
    if sp.clock_skew.is_some_and(|t| t.0 < 0) {
        return Err("ClockSkew must be non-negative".into());
    }
    if sp.request_max_age.is_some_and(|t| t.0 <= 0) {
        return Err("RequestMaxAge must be positive".into());
    }
    Ok(())
}
