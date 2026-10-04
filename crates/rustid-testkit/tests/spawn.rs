use rustid_testkit::server::TestServer;
use rustid_testkit::test_config;

#[tokio::test]
async fn spawned_server_answers_health_and_shuts_down() {
    let server = TestServer::spawn(test_config()).await.unwrap();
    assert!(server.base_url().starts_with("http://127.0.0.1:"));

    let response = reqwest::get(server.url("/health")).await.unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body, serde_json::json!({ "status": "ok" }));

    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn two_servers_get_distinct_ports() {
    let a = TestServer::spawn(test_config()).await.unwrap();
    let b = TestServer::spawn(test_config()).await.unwrap();
    assert_ne!(a.base_url(), b.base_url());
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}
