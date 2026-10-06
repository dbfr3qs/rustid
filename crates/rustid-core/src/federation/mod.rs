//! Upstream federation: signing users in through other OpenID Connect
//! providers, with rustid as the relying party (OIDC Core 1.0, Discovery
//! 1.0).

pub mod challenge;
pub mod flow;
pub mod id_token;
pub mod logout;
pub mod provider;
pub mod session;
pub mod upstream;

pub use flow::Federation;
