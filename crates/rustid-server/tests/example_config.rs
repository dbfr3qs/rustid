use std::path::Path;

use rustid_server::config::ServerConfig;

/// `build_state` on a throwaway runtime, for tests that run inside
/// synchronous `figment::Jail` closures.
fn build(cfg: &ServerConfig) -> anyhow::Result<rustid_http::AppState> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(rustid_server::build_state(cfg))
}

#[test]
fn example_config_file_is_valid_and_builds() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/rustid.toml");
    let cfg = ServerConfig::load(Some(&path)).unwrap();
    assert_eq!(
        cfg.protocol.issuer_uri.as_deref(),
        Some("https://idsrv.test")
    );
    assert_eq!(cfg.listen.port(), 8080);
    build(&cfg).unwrap();
}

#[test]
fn demo_upstream_config_is_valid_and_builds() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo/upstream.toml");
    let cfg = ServerConfig::load(Some(&path)).unwrap();
    assert_eq!(cfg.listen.port(), 5444);
    assert_eq!(
        cfg.protocol.issuer_uri.as_deref(),
        Some("https://127.0.0.1:5444")
    );
    build(&cfg).unwrap();
}

#[test]
fn demo_config_is_valid_and_builds() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo/rustid.toml");
    let cfg = ServerConfig::load(Some(&path)).unwrap();
    assert_eq!(cfg.listen.port(), 5443);
    assert!(cfg.reference_ui.enabled && cfg.reference_ui.interactive);
    let tls = cfg.tls.as_ref().unwrap();
    assert!(tls.cert_file.ends_with("target/demo/cert.pem"));
    assert!(tls.cert_file.is_absolute());
    assert!(cfg.identity_providers_file.is_some());
    build(&cfg).unwrap();
}
