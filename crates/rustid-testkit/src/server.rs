use rustid_server::config::ServerConfig;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// An in-process `rustid-server` bound to an ephemeral port.
pub struct TestServer {
    base_url: String,
    telemetry: Option<rustid_server::telemetry::TelemetryGuard>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<anyhow::Result<()>>,
}

impl TestServer {
    /// Starts the server. The port in `config.listen` is ignored and replaced
    /// with an ephemeral one; the IP address is honoured.
    pub async fn spawn(config: ServerConfig) -> anyhow::Result<Self> {
        let telemetry = rustid_server::telemetry::init_telemetry(&config.log, &config.telemetry);
        let app = rustid_server::build(&config).await?;
        let listener = TcpListener::bind((config.listen.ip(), 0)).await?;
        let addr = listener.local_addr()?;
        let (tx, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(rustid_server::serve(listener, app, async move {
            let _ = rx.await;
        }));
        Ok(Self {
            base_url: format!("http://{addr}"),
            telemetry: Some(telemetry),
            shutdown: Some(tx),
            task,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Joins the base URL and an absolute path such as `/health`.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Stops the server, then flushes any telemetry it exported.
    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let served = self.task.await?;
        if let Some(telemetry) = self.telemetry.take() {
            tokio::task::spawn_blocking(move || telemetry.shutdown()).await?;
        }
        served
    }
}
