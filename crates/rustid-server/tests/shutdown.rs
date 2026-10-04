#![cfg(unix)]

use std::io::Read;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_listen(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "server never started listening");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn sigterm_triggers_graceful_shutdown() {
    let port = free_port();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rustid-server"))
        .args([
            "--config",
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../fixtures/profiles/default.json"
            ),
        ])
        .env("RUSTID_LISTEN", format!("127.0.0.1:{port}"))
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for_listen(port);

    let killed = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());

    let status = child.wait().unwrap();
    let mut out = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    assert!(status.success(), "exit status {status:?}, output: {out}");
    assert!(out.contains("shutdown requested"), "output: {out}");
}
