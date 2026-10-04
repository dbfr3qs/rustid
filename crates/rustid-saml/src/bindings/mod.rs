//! The SAML front-channel bindings' message codecs: HTTP-Redirect (DEFLATE,
//! base64 and a query-string signature) and HTTP-POST (base64 in a form).

pub mod post;
pub mod redirect;

/// The message parameter's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageName {
    SamlRequest,
    SamlResponse,
}

impl MessageName {
    pub fn as_str(self) -> &'static str {
        match self {
            MessageName::SamlRequest => "SAMLRequest",
            MessageName::SamlResponse => "SAMLResponse",
        }
    }
}

/// A message that can't be unbound, with its message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct BindingError(pub String);

pub(crate) fn error(message: impl Into<String>) -> BindingError {
    BindingError(message.into())
}

/// The base64 decoding error.
pub const INVALID_BASE64: &str = "The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters.";

/// `Convert.FromBase64String`: standard base64, whitespace ignored.
pub(crate) fn from_base64(text: &str) -> Result<Vec<u8>, BindingError> {
    use base64::Engine;
    let compact: String = text
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | '\r' | '\n'))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .map_err(|_| error(INVALID_BASE64))
}
