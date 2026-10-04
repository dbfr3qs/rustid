//! The demo client's defaults match its registration in the demo config.

use std::path::Path;

use rustid_demo::client;

#[test]
fn the_registered_client_matches_the_demo_defaults() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/demo/clients.json");
    let clients: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let demo = &clients[0];
    assert_eq!(demo["clientId"], client::DEFAULT_CLIENT_ID);
    assert_eq!(
        demo["redirectUris"][0],
        format!("{}/callback", client::DEFAULT_PUBLIC_URL)
    );
    assert_eq!(
        demo["postLogoutRedirectUris"][0],
        format!("{}/signed-out", client::DEFAULT_PUBLIC_URL)
    );
    assert_eq!(
        demo["frontChannelLogoutUri"],
        format!("{}/frontchannel-logout", client::DEFAULT_PUBLIC_URL)
    );
    let allowed: Vec<&str> = demo["allowedScopes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    for scope in client::DEFAULT_SCOPE.split(' ') {
        if scope == "offline_access" {
            assert_eq!(demo["allowOfflineAccess"], true);
        } else {
            assert!(allowed.contains(&scope), "{scope} is not allowed");
        }
    }
}
