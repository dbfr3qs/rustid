#![forbid(unsafe_code)]

pub mod client;
pub mod cookie_jar;
pub mod diff;
pub mod normalize;
pub mod postgres;
pub mod recorded;
pub mod saml;
pub mod server;
pub mod snapshot;
pub mod store_contract;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use rustid_server::config::ServerConfig;

/// Directory holding the shared fixture profiles.
pub fn profiles_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/profiles")
}

/// Loads `fixtures/profiles/<name>.json` with an ephemeral listen port.
pub fn profile_config(name: &str) -> ServerConfig {
    let path = profiles_dir().join(format!("{name}.json"));
    let mut config =
        ServerConfig::load(Some(&path)).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    config.listen = SocketAddr::from(([127, 0, 0, 1], 0));
    config
}

/// The `default` profile: fixed issuer `https://idsrv.test`, fixture RSA key.
pub fn test_config() -> ServerConfig {
    profile_config("default")
}

/// A file under `fixtures/`.
pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}
