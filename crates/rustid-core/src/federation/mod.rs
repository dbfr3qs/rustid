//! Upstream federation: signing users in through other OpenID Connect
//! providers, with rustid as the relying party (OIDC Core 1.0, Discovery
//! 1.0).

pub mod provider;
pub mod session;
