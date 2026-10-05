//! Dynamic client registration (RFC 7591), as
//! the registration endpoint: the request, its validator, the
//! processor that saves the client, and the response.

mod manage;
mod process;
mod request;
mod response;
mod validate;

pub use manage::{METADATA_PROPERTY, TOKEN_PROPERTY, authorize_management, read};
pub use process::{DcrOptions, ManagementUri, parse, register};
pub use request::{KeySet, RegistrationRequest};
pub use validate::validate;

/// RFC 7591's error for invalid client metadata.
pub const INVALID_CLIENT_METADATA: &str = "invalid_client_metadata";
/// RFC 7591's error for an invalid redirect URI.
pub const INVALID_REDIRECT_URI: &str = "invalid_redirect_uri";

/// A 400 with this JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationError {
    pub error: &'static str,
    pub error_description: String,
}

impl RegistrationError {
    /// An `invalid_client_metadata` error with this description.
    pub fn metadata(description: &str) -> Self {
        Self::new(INVALID_CLIENT_METADATA, description)
    }

    pub fn new(error: &'static str, description: &str) -> Self {
        RegistrationError {
            error,
            error_description: description.to_owned(),
        }
    }
}
