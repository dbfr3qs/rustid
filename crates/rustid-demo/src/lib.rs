#![forbid(unsafe_code)]
//! A demo of rustid you can run and click through: certificates for local
//! HTTPS, and a small relying party that signs in with the authorization
//! code flow and PKCE and shows what it received, the password grant and
//! CIBA user hooks it hosts for the server, and a TV-style device and a
//! backchannel (CIBA) app that sign users in from the command line, and a
//! SAML service provider.

pub mod certs;
pub mod ciba;
pub mod client;
pub mod device;
mod html;
pub mod password_hook;
pub mod saml_sp;
