#![forbid(unsafe_code)]

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rustid_server::config::ServerConfig;
use rustid_server::telemetry::init_telemetry;
use tokio::net::TcpListener;

#[derive(Parser, Debug)]
#[command(
    name = "rustid-server",
    version,
    about = "An OpenID Connect, OAuth 2.0 and SAML 2.0 server"
)]
struct Args {
    /// Path to a TOML configuration file. Environment variables prefixed
    /// RUSTID_ override it.
    #[arg(long, env = "RUSTID_CONFIG")]
    config: Option<PathBuf>,
    /// Check URL and exit: 0 when it answers 2xx within 5 seconds, 1
    /// otherwise. For container health checks
    /// (`--probe http://127.0.0.1:8080/ready`); no configuration is loaded.
    /// An `http://` loopback URL is retried over HTTPS (without certificate
    /// verification) when the listener has `[tls]`.
    #[arg(long, value_name = "URL")]
    probe: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Import a migration bundle (configuration, signing keys and grants
    /// exported from an existing database) into the configured store, then exit.
    Import {
        /// The bundle (`docs/migration.md`).
        bundle: PathBuf,
        /// For the memory store: write the configuration and keys here as
        /// files the server loads, instead of importing.
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(url) = args.probe {
        std::process::exit(rustid_server::probe::probe(&url).await);
    }
    let config = ServerConfig::load(args.config.as_deref())?;
    if let Some(Command::Import { bundle, out_dir }) = &args.command {
        let report = rustid_server::import::run(&config, bundle, out_dir.as_deref()).await?;
        print!("{report}");
        return Ok(());
    }
    let telemetry = init_telemetry(&config.log, &config.telemetry);

    let shutdown = shutdown_signal();
    let app = rustid_server::build(&config).await?;

    let listener = TcpListener::bind(config.listen).await?;
    tracing::info!(listen = %config.listen, "rustid-server starting");
    let served = rustid_server::serve(listener, app, shutdown).await;
    tokio::task::spawn_blocking(move || telemetry.shutdown()).await?;
    served
}

/// Resolves on ctrl-c, or on SIGTERM where available, which is what container
/// runtimes and process supervisors send. The handlers are installed when this
/// is called, not when the future is first polled, so a signal that arrives
/// while the server is still starting up shuts it down gracefully instead of
/// killing it.
fn shutdown_signal() -> impl std::future::Future<Output = ()> {
    #[cfg(unix)]
    let signals = {
        use tokio::signal::unix::{SignalKind, signal};
        (
            signal(SignalKind::interrupt()),
            signal(SignalKind::terminate()),
        )
    };
    async move {
        #[cfg(unix)]
        match signals {
            (Ok(mut interrupt), Ok(mut terminate)) => {
                tokio::select! {
                    _ = interrupt.recv() => {}
                    _ = terminate.recv() => {}
                }
            }
            (interrupt, terminate) => {
                for error in [interrupt.err(), terminate.err()].into_iter().flatten() {
                    tracing::error!(%error, "failed to install a shutdown signal handler");
                }
                std::future::pending::<()>().await;
            }
        }
        #[cfg(not(unix))]
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to listen for ctrl-c");
            std::future::pending::<()>().await;
        }
        tracing::info!("shutdown requested");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_flag_prints_the_package_version() {
        let err = Args::try_parse_from(["rustid-server", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(err.to_string().contains(env!("CARGO_PKG_VERSION")));
    }
}
