//! HTTP-POST: the message is base64 in a form field.

use super::{BindingError, error, from_base64};

/// The message's XML from its form value, refusing more than `max_size`
/// characters' worth of base64.
pub fn decode(encoded: &str, max_size: usize) -> Result<String, BindingError> {
    if encoded.chars().count() > max_size * 4 / 3 {
        return Err(error(format!(
            "SAML message exceeds maximum allowed size of {max_size} characters."
        )));
    }
    let bytes = from_base64(encoded)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
