//! The HTTP target: the whole server (the default fixture profile, with the
//! admin API and SAML on and the reference UI off) in process, one request
//! per input. The first byte picks the route; the rest is the body or the
//! query; for the token and PAR routes, a first line before `\n` is sent
//! as the `DPoP` header. Nothing reaches the network: no hooks are
//! configured, and request URIs (`enable_jwt_request_uri`) are off.
//!
//! The server keeps state between inputs (admin writes, pushed requests,
//! device and CIBA requests), as a real one does, so it is rebuilt every
//! [`REBUILD_EVERY`] inputs: memory stays bounded and a finding depends on
//! at most that many earlier inputs. An artifact that doesn't reproduce on
//! its own needs the corpus run before it.

use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Method, Request, header};
use tower::ServiceExt;

const ADMIN_KEY: &str = "fuzz-admin-key-0123456789abcdefghijkl";
const MAX_INPUT: usize = 64 * 1024;

/// Inputs served before the server is rebuilt from scratch.
pub const REBUILD_EVERY: usize = 10_000;

struct Harness {
    runtime: tokio::runtime::Runtime,
    router: Router,
    served: usize,
}

impl Harness {
    fn rebuild(&mut self) {
        self.router = self.runtime.block_on(build_router());
        self.served = 0;
    }
}

fn fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures")
        .join(name)
}

/// The server from the default fixture profile, admin and SAML on, the
/// reference UI off, nothing reaching the network.
async fn build_router() -> Router {
    let mut config =
        rustid_server::config::ServerConfig::load(Some(&fixture("profiles/default.json")))
            .expect("the default profile");
    config.reference_ui.enabled = false;
    config.admin.enabled = true;
    config.admin.api_keys = vec![ADMIN_KEY.to_owned()];
    config.saml.enabled = true;
    config.saml.service_providers_file = Some(fixture("saml-service-providers.json"));
    // Nothing reaches the network.
    config.protocol.endpoints.enable_jwt_request_uri = false;
    config.hooks = Default::default();
    let local: SocketAddr = ([127, 0, 0, 1], 8080).into();
    let app = rustid_server::build(&config).await.expect("the app");
    rustid_server::router(&app, local)
}

/// One harness per process; requests take turns on its runtime.
fn harness() -> &'static Mutex<Harness> {
    static HARNESS: OnceLock<Mutex<Harness>> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let router = runtime.block_on(build_router());
        Mutex::new(Harness {
            runtime,
            router,
            served: 0,
        })
    })
}

fn lock() -> std::sync::MutexGuard<'static, Harness> {
    harness().lock().unwrap_or_else(|e| e.into_inner())
}

/// Rebuilds the server now, forgetting every earlier input.
pub fn reset() {
    lock().rebuild();
}

/// The route for selector byte `selector`, and whether a 500 there is a
/// bug (every OIDC and admin route; SAML answers 500 for the XML reader's
/// unhandled errors).
fn build_request(selector: u8, rest: &[u8]) -> (Request<Body>, bool) {
    use base64::Engine;
    let text = String::from_utf8_lossy(rest).into_owned();
    let form = |path: &str| {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(rest.to_vec()))
    };
    let query = |path: &str| {
        let q: String = text
            .chars()
            .filter(|c| c.is_ascii_graphic() && *c != '#')
            .collect();
        Request::builder()
            .method(Method::GET)
            .uri(format!("{path}?{q}"))
            .body(Body::empty())
    };
    let admin = |path: &str| {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {ADMIN_KEY}"))
            .body(Body::from(rest.to_vec()))
    };
    let dpop_form = |path: &str| {
        let Some(newline) = rest.iter().position(|&b| b == b'\n') else {
            return form(path);
        };
        let (header_line, body) = (&rest[..newline], &rest[newline + 1..]);
        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Ok(value) = header::HeaderValue::from_bytes(header_line) {
            builder = builder.header("DPoP", value);
        }
        builder.body(Body::from(body.to_vec()))
    };
    let (request, strict) = match selector % 10 {
        0 => (dpop_form("/connect/token"), true),
        1 => (query("/connect/authorize"), true),
        2 => (dpop_form("/connect/par"), true),
        3 => (form("/connect/deviceauthorization"), true),
        4 => (form("/connect/ciba"), true),
        5 => {
            let basic = base64::engine::general_purpose::STANDARD.encode("api:secret");
            let mut request = form("/connect/introspect");
            if let Ok(r) = request.as_mut() {
                r.headers_mut().insert(
                    header::AUTHORIZATION,
                    format!("Basic {basic}").parse().unwrap(),
                );
            }
            (request, true)
        }
        6 => (query("/Saml2/SSO"), false),
        7 => (form("/Saml2/SSO"), false),
        8 => (admin("/admin/clients"), true),
        _ => (admin("/admin/saml-service-providers"), true),
    };
    // A query that still isn't a valid URI goes without one.
    let request = request.unwrap_or_else(|_| {
        Request::builder()
            .uri("/connect/authorize")
            .body(Body::empty())
            .unwrap()
    });
    (request, strict)
}

fn call(harness: &Harness, router: Router, mut request: Request<Body>) -> (u16, Vec<u8>) {
    request
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 1))));
    // As every HTTP/1.1 client sends; URLs and the issuer are built from it.
    request.headers_mut().insert(
        header::HOST,
        header::HeaderValue::from_static("localhost:8080"),
    );
    harness.runtime.block_on(async {
        let response = router.oneshot(request).await.expect("infallible");
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        (status, body.to_vec())
    })
}

struct Sent {
    status: u16,
    body: Vec<u8>,
    strict: bool,
    path: String,
}

/// Sends the request `data` encodes, rebuilding the server every
/// [`REBUILD_EVERY`] inputs; `None` for empty input.
fn send(data: &[u8]) -> Option<Sent> {
    let (&selector, rest) = data.split_first()?;
    let rest = &rest[..rest.len().min(MAX_INPUT)];
    let (request, strict) = build_request(selector, rest);
    let path = request.uri().path().to_owned();
    let mut harness = lock();
    if harness.served >= REBUILD_EVERY {
        harness.rebuild();
    }
    harness.served += 1;
    let router = harness.router.clone();
    let (status, body) = call(&harness, router, request);
    Some(Sent {
        status,
        body,
        strict,
        path,
    })
}

/// The status of the request `data` encodes; `None` for empty input.
pub fn request(data: &[u8]) -> Option<u16> {
    send(data).map(|sent| sent.status)
}

/// The body of the response to the request `data` encodes.
pub fn request_body(data: &[u8]) -> Option<String> {
    send(data).map(|sent| String::from_utf8_lossy(&sent.body).into_owned())
}

/// The fuzz target: a panic anywhere, or a 500 on an OIDC or admin route.
pub fn http(data: &[u8]) {
    let Some(sent) = send(data) else {
        return;
    };
    assert!(
        !(sent.strict && sent.status == 500),
        "{} answered 500 for {:?}",
        sent.path,
        String::from_utf8_lossy(data)
    );
}

/// Calls a router whose only handler is `handler` the way [`request`]
/// calls the server's, to show that a handler's panic reaches the caller.
pub fn request_with_handler(handler: fn()) {
    let harness = lock();
    let router = Router::new().route(
        "/",
        axum::routing::get(move || async move {
            handler();
            ""
        }),
    );
    let request = Request::builder().uri("/").body(Body::empty()).unwrap();
    call(&harness, router, request);
}
