#![forbid(unsafe_code)]
//! The SAML 2.0 IdP (scoping spec section 4.9).
pub mod admin;
pub mod bindings;
pub mod connected;
pub mod constants;
pub mod idp_initiated;
pub mod ids;
pub mod logout;
pub mod metadata;
pub mod model;
pub mod options;
pub mod protocol;
pub mod response;
pub mod signing;
pub mod sso;
pub mod state;
pub mod stores;
pub mod validation;
pub mod xml;

/// The SAML IdP's configuration and stores, when it's enabled.
#[derive(Clone)]
pub struct Saml {
    pub options: options::SamlOptions,
    pub stores: stores::SamlStores,
}
