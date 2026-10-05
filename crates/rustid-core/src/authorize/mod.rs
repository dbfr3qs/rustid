//! The authorize endpoint's protocol logic without HTTP types: request
//! validation, the interaction decision
//! and the error messages the
//! error page reads back.

pub mod code;
pub mod context;
pub mod implicit;
pub mod interaction;
pub mod jarm;
pub mod login;
pub mod messages;
pub mod request;
pub mod request_object;
pub mod validation;

pub use interaction::{Interaction, process_interaction};
pub use request::{AuthorizeRequestType, ValidatedAuthorizeRequest};
pub use validation::{
    AuthorizeContext, AuthorizeError, AuthorizeFailure, return_url_query, validate, validate_pushed,
};

/// Prompt values already acted on, added to
/// the return URL so the callback doesn't act on them again.
pub const PROCESSED_PROMPT: &str = "suppressed_prompt";
/// Marks `max_age` as already acted on, in the return URL.
pub const PROCESSED_MAX_AGE: &str = "suppressed_max_age";
/// The `request_uri` prefix of pushed authorization requests (RFC 9126).
pub const PAR_REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri";

/// Authorize errors that the endpoint returns to the client
/// instead of showing the error page.
pub const SAFE_ERRORS: &[&str] = &[
    "access_denied",
    "account_selection_required",
    "login_required",
    "consent_required",
    "interaction_required",
    "temporarily_unavailable",
    "unmet_authentication_requirements",
];

pub const INVALID_REQUEST: &str = "invalid_request";
pub const UNAUTHORIZED_CLIENT: &str = "unauthorized_client";
pub const UNSUPPORTED_RESPONSE_TYPE: &str = "unsupported_response_type";
pub const INVALID_SCOPE: &str = "invalid_scope";
pub const INVALID_TARGET: &str = "invalid_target";
pub const INVALID_REQUEST_URI: &str = "invalid_request_uri";
pub const INVALID_REQUEST_OBJECT: &str = "invalid_request_object";
pub const REQUEST_URI_NOT_SUPPORTED: &str = "request_uri_not_supported";
pub const LOGIN_REQUIRED: &str = "login_required";
pub const CONSENT_REQUIRED: &str = "consent_required";
pub const INTERACTION_REQUIRED: &str = "interaction_required";
