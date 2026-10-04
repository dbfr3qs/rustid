#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rustid_demo::client::{self, ClientConfig};

#[derive(Parser)]
#[command(name = "rustid-demo", about = "Try rustid in a browser")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Writes a local CA (ca.pem) and a server certificate it signed
    /// (cert.pem, key.pem). Existing files are kept unless --force.
    Certs {
        #[arg(long, default_value = "target/demo")]
        out: PathBuf,
        /// Host names the certificate is for.
        #[arg(long = "host", default_values = ["localhost", "127.0.0.1"])]
        hosts: Vec<String>,
        #[arg(long)]
        force: bool,
    },
    /// Signs in like a TV: shows a code to enter at the server's device
    /// page, then polls until you allow it, and prints what it got.
    Device {
        /// The server's base URL.
        #[arg(long, default_value = client::DEFAULT_AUTHORITY)]
        authority: String,
        #[arg(long, default_value = "demo.tv")]
        client_id: String,
        #[arg(long, env = "RUSTID_DEMO_CLIENT_SECRET", default_value = "secret")]
        client_secret: String,
        #[arg(long, default_value = "openid profile email api1")]
        scope: String,
        /// A CA certificate to trust for the server.
        #[arg(long, default_value = "target/demo/ca.pem")]
        ca_file: PathBuf,
    },
    /// Signs a user in from the backchannel (CIBA), as a call centre would:
    /// names the user, who allows it on the server's CIBA page, then polls
    /// and prints what it got.
    Ciba {
        /// The user's username (the demo client's hook looks it up).
        #[arg(long, default_value = "alice")]
        login_hint: String,
        /// A message the user sees, to match this request.
        #[arg(long)]
        binding_message: Option<String>,
        /// The server's base URL.
        #[arg(long, default_value = client::DEFAULT_AUTHORITY)]
        authority: String,
        #[arg(long, default_value = "demo.ciba")]
        client_id: String,
        #[arg(long, env = "RUSTID_DEMO_CLIENT_SECRET", default_value = "secret")]
        client_secret: String,
        #[arg(long, default_value = "openid profile email api1")]
        scope: String,
        /// A CA certificate to trust for the server.
        #[arg(long, default_value = "target/demo/ca.pem")]
        ca_file: PathBuf,
    },
    /// Runs the demo client: a web app that signs in at the server with the
    /// authorization code flow and PKCE and shows what it received.
    Client {
        #[arg(long, default_value = "127.0.0.1:5002")]
        listen: SocketAddr,
        /// The client's URL as the browser sees it.
        #[arg(long, default_value = client::DEFAULT_PUBLIC_URL)]
        public_url: String,
        /// The server's base URL.
        #[arg(long, default_value = client::DEFAULT_AUTHORITY)]
        authority: String,
        #[arg(long, default_value = client::DEFAULT_CLIENT_ID)]
        client_id: String,
        #[arg(long, env = "RUSTID_DEMO_CLIENT_SECRET", default_value = "secret")]
        client_secret: String,
        #[arg(long, default_value = client::DEFAULT_SCOPE)]
        scope: String,
        /// A CA certificate to trust for the server.
        #[arg(long, default_value = "target/demo/ca.pem")]
        ca_file: PathBuf,
        /// Users the password grant hook (`/hooks/password`) checks; no hook
        /// without it.
        #[arg(long)]
        users_file: Option<PathBuf>,
        /// The SAML service provider's signing key (`/saml`); no SAML SP
        /// without it.
        #[arg(long)]
        saml_key: Option<PathBuf>,
        /// The SAML service provider's certificate.
        #[arg(long, default_value = "fixtures/saml/sp/sp-signing.cert.pem")]
        saml_cert: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match Args::parse().command {
        Command::Certs { out, hosts, force } => {
            let files = rustid_demo::certs::write(&out, &hosts, force)?;
            println!("CA:          {}", files.ca.display());
            println!("certificate: {}", files.cert.display());
            println!("key:         {}", files.key.display());
        }
        Command::Device {
            authority,
            client_id,
            client_secret,
            scope,
            ca_file,
        } => {
            let device =
                rustid_demo::device::DeviceClient::new(rustid_demo::device::DeviceConfig {
                    authority,
                    client_id,
                    client_secret: Some(client_secret),
                    scope,
                    ca_file: ca_file.is_file().then_some(ca_file),
                    resolve: Vec::new(),
                })?;
            let started = device.start().await?;
            println!();
            println!("  On your phone or computer, open:");
            println!("    {}", started.verification_uri);
            println!("  and enter the code:  {}", started.user_code);
            if let Some(complete) = &started.verification_uri_complete {
                println!("  (or open {complete})");
            }
            println!("  Sign in to the demo client first if the page asks you to.");
            println!();
            println!(
                "  Waiting (the code expires in {} s)...",
                started.expires_in
            );
            let tokens = device.wait(&started).await?;
            println!("  Allowed. Scopes: {}", tokens.scope);
            let userinfo = device.userinfo(&tokens).await?;
            println!("  Userinfo: {}", serde_json::to_string_pretty(&userinfo)?);
        }
        Command::Ciba {
            login_hint,
            binding_message,
            authority,
            client_id,
            client_secret,
            scope,
            ca_file,
        } => {
            let app = rustid_demo::ciba::CibaClient::new(rustid_demo::ciba::CibaConfig {
                authority: authority.clone(),
                client_id,
                client_secret,
                scope,
                ca_file: ca_file.is_file().then_some(ca_file),
                resolve: Vec::new(),
            })?;
            let message = binding_message
                .unwrap_or_else(|| format!("demo-{}", chrono::Utc::now().timestamp() % 10_000));
            let started = app.start(&login_hint, Some(&message)).await?;
            println!();
            println!("  Asked the server to sign in {login_hint}.");
            println!("  1. Sign in as {login_hint} at the demo client, http://localhost:5002");
            println!("     (the server's pages can't sign you in on their own).");
            println!("  2. Open {}/ciba", authority.trim_end_matches('/'));
            println!("     check the message reads \"{message}\", and allow it.");
            println!();
            println!(
                "  Waiting (the request expires in {} s)...",
                started.expires_in
            );
            let tokens = app.wait(&started).await?;
            println!("  Allowed. Scopes: {}", tokens.scope);
            println!(
                "  Identity token claims: {}",
                serde_json::to_string_pretty(&tokens.id_claims)?
            );
        }
        Command::Client {
            listen,
            public_url,
            authority,
            client_id,
            client_secret,
            scope,
            ca_file,
            users_file,
            saml_key,
            saml_cert,
        } => {
            let saml = saml_key.map(|key_file| rustid_demo::saml_sp::SamlSpConfig {
                idp: authority.clone(),
                entity_id: format!("{}/saml", public_url.trim_end_matches('/')),
                key_file,
                cert_file: saml_cert,
            });
            let router = client::router(ClientConfig {
                authority,
                client_id,
                client_secret: Some(client_secret),
                public_url: public_url.clone(),
                scope,
                ca_file: ca_file.is_file().then_some(ca_file),
                resolve: Vec::new(),
                users_file,
                saml,
            })?;
            let listener = tokio::net::TcpListener::bind(listen).await?;
            tracing::info!(%listen, "demo client at {public_url}");
            axum::serve(listener, router).await?;
        }
    }
    Ok(())
}
