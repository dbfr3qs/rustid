//! SAML message ids.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// 20 random bytes, the first with its top bit cleared so the id starts
/// with a letter (an xs:ID), base64url-encoded.
pub fn create_id() -> String {
    let mut bytes = [0u8; 20];
    aws_lc_rs::rand::fill(&mut bytes).expect("the system RNG");
    bytes[0] &= 0x7F;
    URL_SAFE_NO_PAD.encode(bytes)
}
