#![forbid(unsafe_code)]

pub mod back_channel;
pub mod config;
mod configuration;
pub mod federation;
pub mod forwarded;
mod html;
pub mod import;
pub mod probe;
pub mod reference_ui;
pub mod request_uri;
pub mod telemetry;
pub mod tls;

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use rustid_core::clients::Clients;
use rustid_core::data_protection::DataProtector;
use rustid_core::discovery::DiscoveryFeatures;
use rustid_core::events::{EventService, LogEventSink};
use rustid_core::key_management::{KeyManager, SystemClock};
use rustid_core::key_service::KeyService;
use rustid_core::keys::KeyMaterial;
use rustid_core::resources::Resources;
use rustid_core::stores::{SigningKeyStore, Stores};
use rustid_http::{AppState, InteractionState, ProtocolState};
use rustid_store_memory::{
    CacheDurations, CachingClientStore, CachingResourceStore, FileSystemSigningKeyStore,
};
use rustid_store_postgres::PgStore;
use tokio::net::TcpListener;

use crate::config::{ServerConfig, StoreKind};

/// Everything `serve` runs: the protocol state and the optional reference UI.
pub struct App {
    pub state: AppState,
    reference_ui: Option<reference_ui::ReferenceUi>,
    tls: Option<std::sync::Arc<tokio_rustls::rustls::ServerConfig>>,
    trusted: std::sync::Arc<forwarded::Trusted>,
    /// The consumed-grant settings the storage purge uses.
    purge: PurgeConsumed,
    /// The admin API, when enabled.
    admin: Option<rustid_admin::AdminState>,
    /// The SAML IdP, when enabled.
    saml: Option<rustid_saml::Saml>,
}

#[derive(Debug, Clone, Copy)]
struct PurgeConsumed {
    remove: bool,
    delay: i64,
}

impl App {
    /// The SAML IdP, when `[saml] enabled`.
    pub fn saml(&self) -> Option<&rustid_saml::Saml> {
        self.saml.as_ref()
    }
}

/// Builds the application from configuration.
/// Settings that are accepted but, with the rest of the configuration,
/// silently do nothing (or do something other than they seem to).
pub fn config_warnings(config: &ServerConfig) -> Vec<String> {
    let mut warnings = Vec::new();
    // A client the runtime treats as unknown: every request it makes fails,
    // with only a per-request log line otherwise.
    if let Some(path) = &config.clients_file
        && let Ok(clients) = rustid_core::clients::Clients::load(path)
    {
        let par = config
            .protocol
            .pushed_authorization
            .allow_unregistered_pushed_redirect_uris;
        for client in &clients.clients {
            if let Err(problem) = rustid_core::clients::validate_client(client, par) {
                warnings.push(format!(
                    "client {} in clients_file will be refused (treated as unknown): {problem}",
                    client.client_id
                ));
            }
        }
    }
    if config.admin.schemas_file.is_some() && !config.admin.enabled {
        warnings.push(
            "admin.schemas_file is set but the admin API is disabled: the schemas aren't loaded"
                .to_owned(),
        );
    }
    let sessions = &config.protocol.server_side_sessions;
    if config.server_side_sessions.enabled
        && sessions.remove_expired_sessions
        && !config.protocol.outbox_processor.enable_processor
    {
        warnings.push(
            "protocol.outbox_processor.enable_processor is off: expired server-side \
             sessions queue logout notifications that nothing delivers, and their \
             coordinated clients' tokens are never revoked"
                .to_owned(),
        );
    }
    if let Some(tls) = &config.tls
        && tls.cipher_suites == config::CipherSuites::Fapi
        && tls::key_is_rsa(tls) == Some(false)
    {
        warnings.push(
            "tls.cipher_suites = \"fapi\" allows only ECDHE-RSA suites on TLS 1.2, and the \
             certificate's key isn't RSA: the listener offers TLS 1.3 only"
                .to_owned(),
        );
    }
    let dcr = &config.dynamic_client_registration;
    let inferred = config
        .protocol
        .discovery
        .dynamic_client_registration
        .registration_endpoint_mode
        == rustid_core::options::RegistrationEndpointMode::Inferred;
    if inferred && !dcr.enabled {
        warnings.push(
            "protocol.discovery.dynamic_client_registration.registration_endpoint_mode = \
             \"Inferred\" publishes {base}/connect/dcr, but dynamic_client_registration is off"
                .to_owned(),
        );
    } else if inferred && dcr.path != "/connect/dcr" {
        warnings.push(format!(
            "protocol.discovery.dynamic_client_registration.registration_endpoint_mode = \
             \"Inferred\" publishes {{base}}/connect/dcr, but the endpoint is at {}; use \
             \"Static\" with static_registration_endpoint",
            dcr.path
        ));
    }
    warnings
}

/// The reference UI's pages (lower-cased), which the UI router serves
/// ahead of the protocol routes; `/test/...` is its scripted harness.
const REFERENCE_UI_PATHS: &[&str] = &[
    "/home/error",
    "/account/login",
    "/account/login/context",
    "/account/logout",
    "/account/consent",
    "/consent",
    "/device",
    "/ciba",
    "/sessions",
];

/// A dynamic client registration path that another route already serves
/// would never be reached (or would hide that route): refused.
fn check_dcr_path(config: &ServerConfig, state: &AppState) -> anyhow::Result<()> {
    let dcr = &config.dynamic_client_registration;
    if !dcr.enabled {
        return Ok(());
    }
    let lower = dcr.path.to_ascii_lowercase();
    let admin = config.admin.enabled && (lower == "/admin" || lower.starts_with("/admin/"));
    let ui = config.reference_ui.enabled
        && (REFERENCE_UI_PATHS.contains(&lower.as_str()) || lower.starts_with("/test/"));
    if admin || ui || rustid_http::shadows_route(&state.0, &dcr.path) {
        anyhow::bail!(
            "dynamic_client_registration.path {} is already served by another route",
            dcr.path
        );
    }
    Ok(())
}

/// `[dynamic_client_registration]`, checked: open, or tokens long enough.
fn dcr_settings(
    config: &config::DynamicClientRegistrationConfig,
) -> anyhow::Result<Option<rustid_http::DcrSettings>> {
    if !config.enabled {
        return Ok(None);
    }
    if !config.open && config.initial_access_tokens.is_empty() {
        anyhow::bail!(
            "dynamic_client_registration.enabled needs initial_access_tokens, or open = true"
        );
    }
    if config
        .initial_access_tokens
        .iter()
        .any(|t| t.chars().count() < config::MIN_ADMIN_KEY_LENGTH)
    {
        anyhow::bail!(
            "dynamic_client_registration.initial_access_tokens entries must be at least {} characters",
            config::MIN_ADMIN_KEY_LENGTH
        );
    }
    if !config.path.starts_with('/') {
        anyhow::bail!("dynamic_client_registration.path must start with /");
    }
    if config.open {
        tracing::warn!("dynamic client registration is open: anyone can register clients");
    }
    Ok(Some(rustid_http::DcrSettings {
        path: config.path.clone(),
        open: config.open,
        initial_access_tokens: config.initial_access_tokens.clone(),
        options: rustid_core::dcr::DcrOptions {
            secret_lifetime: config.secret_lifetime.as_ref().map(|t| t.0),
            management: None,
            default_scopes: config.default_scopes.clone(),
            require_pkce: config.require_pkce,
            // Read from the keys for each registration.
            userinfo_signing_algorithms: Vec::new(),
        },
        client_management: config.client_management,
    }))
}

pub async fn build(config: &ServerConfig) -> anyhow::Result<App> {
    let (mut state, saml) = build_state_and_saml(config).await?;
    check_dcr_path(config, &state)?;
    for warning in config_warnings(config) {
        tracing::warn!("{warning}");
    }
    let reference_ui = if config.reference_ui.enabled {
        if config.reference_ui.interactive {
            tracing::warn!(
                "the reference UI is enabled in interactive mode; it signs in the users file's \
                 users and is for tests and demos only"
            );
        } else {
            tracing::warn!(
                "the reference UI is enabled; it signs in without credentials and is for tests only"
            );
        }
        let users = match &config.reference_ui.users_file {
            Some(path) => reference_ui::load_users(path)?,
            None => Vec::new(),
        };
        let key = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            rustid_core::data_protection::generate_key(),
        );
        let protocol = std::sync::Arc::get_mut(&mut state.0).expect("state not yet shared");
        protocol.interaction.api_keys.push(key.clone());
        if config.reference_ui.users_profile_service
            && config.hooks.profile_claims.is_none()
            && config.hooks.subject_active.is_none()
        {
            protocol.stores.profile =
                Arc::new(reference_ui::UsersProfileService::new(users.clone()));
        }
        Some(
            reference_ui::ReferenceUi::new(
                key,
                config.path_base.clone(),
                users,
                config.reference_ui.default_user.clone(),
                config.reference_ui.interactive,
            )
            .with_sessions(protocol.stores.sessions.clone())
            .with_configuration(protocol.stores.configuration.clone()),
        )
    } else {
        None
    };
    let tls = config
        .tls
        .as_ref()
        .map(tls::server_config)
        .transpose()
        .context("loading the TLS certificate")?;
    let client_ca_roots = config
        .mutual_tls
        .client_ca_file
        .as_ref()
        .map(|path| {
            let pem = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
            rustid_core::client_certificate::ClientCaRoots::from_pem(&pem)
                .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
        })
        .transpose()
        .context("loading the client CA roots")?
        .map(std::sync::Arc::new);
    let certificate_header = config
        .mutual_tls
        .forwarded_certificate_header
        .as_deref()
        .map(axum::http::HeaderName::try_from)
        .transpose()
        .context("mutual_tls.forwarded_certificate_header")?;
    let admin = if config.admin.enabled {
        if config.admin.api_keys.is_empty() {
            anyhow::bail!("admin.enabled needs at least one admin.api_keys entry");
        }
        if config
            .admin
            .api_keys
            .iter()
            .any(|k| k.chars().count() < config::MIN_ADMIN_KEY_LENGTH)
        {
            anyhow::bail!(
                "admin.api_keys entries must be at least {} characters",
                config::MIN_ADMIN_KEY_LENGTH
            );
        }
        if let Some(path) = &config.admin.schemas_file {
            register_schemas(state.0.stores.configuration.as_ref(), path).await?;
        }
        tracing::info!("the admin API is enabled under /admin");
        Some(rustid_admin::AdminState {
            configuration: state.0.stores.configuration.clone(),
            api_keys: config.admin.api_keys.clone(),
            clients: rustid_core::admin::clients::ClientAdmin {
                allow_unregistered_pushed_redirect_uris: config
                    .protocol
                    .pushed_authorization
                    .allow_unregistered_pushed_redirect_uris,
                pairwise_supported: config.pairwise.salt.is_some(),
            },
            schemas_read_only: config.admin.schemas_file.is_some(),
            identity_providers: Arc::new(
                rustid_core::admin::identity_providers::IdentityProviderAdmin::new(
                    state.0.interaction.protector.clone(),
                )
                .with_insecure_loopback(config.federation.allow_insecure_loopback)
                // On Postgres, a per-process key wouldn't open stored secrets
                // after a restart.
                .with_inline_secrets(
                    config.store.kind != StoreKind::Postgres || config.data_protector()?.is_some(),
                ),
            ),
        })
    } else {
        None
    };
    Ok(App {
        state,
        reference_ui,
        tls,
        trusted: std::sync::Arc::new(forwarded::Trusted {
            proxies: config.forwarded_headers.trusted_proxies.clone(),
            certificate_header,
            client_ca_roots,
        }),
        purge: PurgeConsumed {
            remove: config.store.remove_consumed_grants,
            delay: config.store.consumed_grant_cleanup_delay,
        },
        admin,
        saml,
    })
}

/// Loads keys, connects the stores and assembles the shared request state.
/// The configuration files are imported into the configuration store on
/// the way: identity providers on either store, and on Postgres the
/// clients, resources and SAML service providers too, at every start.
pub async fn build_state(config: &ServerConfig) -> anyhow::Result<AppState> {
    Ok(build_state_and_saml(config).await?.0)
}

/// The SAML service providers from `service_providers_file` when `[saml]
/// enabled`; invalid ones are reported (lookups skip them).
fn saml_service_providers(
    config: &ServerConfig,
) -> anyhow::Result<Vec<rustid_saml::model::ServiceProvider>> {
    if config.saml.enabled && !cfg!(feature = "saml") {
        anyhow::bail!("[saml] enabled, but this build has no SAML support (the `saml` feature)");
    }
    if !config.saml.enabled {
        if let Some(path) = &config.saml.service_providers_file {
            tracing::warn!(
                path = %path.display(),
                "saml.service_providers_file is ignored: SAML is disabled"
            );
        }
        return Ok(Vec::new());
    }
    let providers = match &config.saml.service_providers_file {
        Some(path) => rustid_saml::model::load_service_providers(path)?,
        None => Vec::new(),
    };
    // Lookups skip an invalid provider; say so once at startup too.
    for sp in &providers {
        if let Err(error) = rustid_saml::validation::validate_service_provider(sp) {
            tracing::warn!(
                entity_id = %sp.entity_id,
                %error,
                "SAML service provider is invalid and won't be served"
            );
        }
    }
    Ok(providers)
}

/// The SAML IdP's stores and options, when `[saml] enabled`: service
/// providers from the configuration admin edits (seeded from
/// `service_providers_file`, imported into Postgres there), sign-in state and
/// logout sessions where the grants live.
async fn build_saml(
    config: &ServerConfig,
    pg: Option<&PgStore>,
    memory: Option<Arc<rustid_store_memory::InMemoryConfiguration>>,
) -> anyhow::Result<Option<rustid_saml::Saml>> {
    use rustid_saml::stores::{SamlStores, ValidatingServiceProviderStore};
    if !config.saml.enabled {
        return Ok(None);
    }
    let stores = match (pg, memory) {
        (Some(pg), _) => {
            if let Some(path) = &config.saml.service_providers_file {
                let raw = read_json(path)?;
                let raw = raw
                    .as_array()
                    .with_context(|| format!("{} must hold a JSON array", path.display()))?;
                pg.import_saml_service_providers(raw)
                    .await
                    .with_context(|| format!("importing {}", path.display()))?;
            }
            SamlStores {
                service_providers: Arc::new(ValidatingServiceProviderStore::new(pg.clone())),
                signin_states: Arc::new(pg.clone()),
                logout_sessions: Arc::new(pg.clone()),
            }
        }
        (None, Some(memory)) => SamlStores {
            service_providers: Arc::new(ValidatingServiceProviderStore::new(memory)),
            signin_states: Arc::new(rustid_store_memory::saml::InMemorySigninStateStore::default()),
            logout_sessions: Arc::new(
                rustid_store_memory::saml::InMemoryLogoutSessionStore::default(),
            ),
        },
        (None, None) => unreachable!("the memory store returns its configuration"),
    };
    tracing::info!("the SAML 2.0 IdP is enabled");
    Ok(Some(rustid_saml::Saml {
        options: config.saml.options.clone(),
        stores,
    }))
}

/// The upstream identity providers, and the client that reaches them.
/// Providers live in the configuration store, where the admin API manages
/// them; `identity_providers_file` is checked (startup fails on a bad
/// entry) and imported into it, its file paths made absolute.
async fn build_federation(
    config: &ServerConfig,
    configuration: Arc<dyn rustid_core::stores::ConfigurationStore>,
    protector: Arc<rustid_core::data_protection::DataProtector>,
) -> anyhow::Result<rustid_core::federation::Federation> {
    let insecure = config.federation.allow_insecure_loopback;
    if let Some(path) = &config.identity_providers_file {
        let providers =
            federation::load_providers(path, insecure, &|name| std::env::var(name).ok())
                .with_context(|| format!("loading {}", path.display()))?;
        // Absolute, whatever the working directory: stored providers resolve
        // their files later, away from it.
        let absolute =
            std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))?;
        let base = absolute.parent().unwrap_or(Path::new("/"));
        let configs: Vec<rustid_core::federation::provider::IdentityProvider> = providers
            .iter()
            .map(|p| {
                let mut config = p.config.clone();
                let auth = &mut config.client_authentication;
                for file in [auth.key_file.as_mut(), auth.certificate_file.as_mut()]
                    .into_iter()
                    .flatten()
                {
                    *file = base.join(&*file);
                }
                config
            })
            .collect();
        rustid_core::admin::identity_providers::import(
            configuration.as_ref(),
            &protector,
            &configs,
        )
        .await
        .with_context(|| format!("importing {}", path.display()))?;
    }
    let upstream =
        federation::HttpUpstreamClient::with_ca_file(config.federation.ca_file.as_deref())?;
    let federation = rustid_core::federation::Federation::from_store(
        configuration,
        protector,
        std::sync::Arc::new(upstream),
        insecure,
    );
    let schemes: Vec<String> = federation
        .providers()
        .await?
        .iter()
        .map(|p| p.config.scheme.clone())
        .collect();
    if let Some(clients) = &config.clients_file {
        let clients = rustid_core::clients::Clients::load(clients)?;
        for (client, scheme) in federation::unknown_restrictions(&clients.clients, &schemes) {
            tracing::warn!(%client, %scheme, "a client's identityProviderRestrictions names an identity provider that isn't configured");
        }
    }
    if !schemes.is_empty() {
        tracing::info!(
            providers = schemes.len(),
            "upstream federation is configured"
        );
    }
    Ok(federation)
}

/// A pairwise client in `clients_file` needs the server's salt.
fn check_pairwise_clients(config: &ServerConfig) -> anyhow::Result<()> {
    if config.pairwise.salt.is_some() {
        return Ok(());
    }
    if let Some(path) = &config.clients_file {
        let clients = rustid_core::clients::Clients::load(path)?;
        if let Some(client) = clients
            .clients
            .iter()
            .find(|c| c.subject_type == rustid_core::clients::SubjectType::Pairwise)
        {
            anyhow::bail!(
                "client {} is pairwise, but [pairwise] salt isn't set",
                client.client_id
            );
        }
    }
    Ok(())
}

async fn build_state_and_saml(
    config: &ServerConfig,
) -> anyhow::Result<(AppState, Option<rustid_saml::Saml>)> {
    check_pairwise_clients(config)?;
    let jarm = &config.protocol.jarm;
    if jarm.enabled && jarm.lifetime.0 <= 0 {
        anyhow::bail!("protocol.jarm.lifetime must be positive");
    }
    let material =
        KeyMaterial::load(&config.signing_keys, &config.validation_keys).context("loading keys")?;
    // Discovery lists the grants the hooks validate, besides the
    // placeholders a configuration declares.
    let mut extension_grants = config.placeholders.extension_grants.clone();
    for grant_type in config.hooks.extension_grants.keys() {
        if !extension_grants.contains(grant_type) {
            extension_grants.push(grant_type.clone());
        }
    }
    let features = DiscoveryFeatures {
        password_grant: config.placeholders.password_grant || config.hooks.password_grant.is_some(),
        extension_grants,
        private_key_jwt: config.client_authentication.private_key_jwt,
    };
    let providers = saml_service_providers(config)?;
    let (mut stores, pg, memory) = build_stores(config, &providers).await?;
    let saml = build_saml(config, pg.as_ref(), memory).await?;
    // Server-side sessions live where the grants do.
    // So does the outbox their expiration goes through.
    type SessionStores = (
        Arc<dyn rustid_core::stores::ServerSideSessionStore>,
        Arc<dyn rustid_core::outbox::OutboxStore>,
    );
    let session_store: Option<SessionStores> =
        config.server_side_sessions.enabled.then(|| match &pg {
            Some(pg) => (
                Arc::new(pg.clone()) as Arc<dyn rustid_core::stores::ServerSideSessionStore>,
                Arc::new(pg.clone()) as Arc<dyn rustid_core::outbox::OutboxStore>,
            ),
            None => {
                let store =
                    Arc::new(rustid_store_memory::InMemoryServerSideSessionStore::default());
                let outbox = store.outbox();
                (store as _, outbox as _)
            }
        });
    let manager = key_manager(config, pg).await?;
    let keys = KeyService::new(material, manager);
    let interaction = interaction_state(config)?;
    stores.federation = std::sync::Arc::new(
        build_federation(
            config,
            stores.configuration.clone(),
            interaction.protector.clone(),
        )
        .await?,
    );
    stores.request_uri = std::sync::Arc::new(request_uri::HttpRequestUriFetcher::with_ca_file(
        config.request_uri.ca_file.as_deref(),
    )?);
    stores.back_channel = std::sync::Arc::new(back_channel::HttpBackChannelSender::with_ca_file(
        config.back_channel_logout.ca_file.as_deref(),
    )?);
    if config.hooks != rustid_hooks::HooksConfig::default() {
        let issuer = config
            .protocol
            .issuer_uri
            .clone()
            .unwrap_or_else(|| "rustid".to_owned());
        let hooks = rustid_hooks::Hooks::new(config.hooks.clone(), keys.clone(), issuer)
            .context("configuring hooks")?;
        tracing::info!(?hooks, "hooks are configured");
        let hooks = std::sync::Arc::new(hooks);
        stores.profile = hooks.clone();
        stores.token_request = hooks.clone();
        if hooks.has_ciba() {
            stores.ciba = hooks.clone();
        }
        stores.grant_validation = hooks;
    }
    let dcr = dcr_settings(&config.dynamic_client_registration)?;
    stores.sessions = session_store.map(|(store, outbox)| {
        Arc::new(rustid_core::server_side_sessions::ServerSideSessions {
            store,
            outbox,
            protector: interaction.protector.clone(),
        })
    });
    let state = AppState::new(ProtocolState {
        options: config.protocol.clone(),
        keys,
        features,
        stores,
        events: EventService::new(config.protocol.events.clone(), Arc::new(LogEventSink)),
        path_base: config.path_base.clone(),
        protected_resource: config.protected_resource.as_ref().map(|r| r.path.clone()),
        dcr,
        interaction,
        #[cfg(feature = "saml")]
        saml: rustid_http::SamlState(saml.clone()),
        #[cfg(not(feature = "saml"))]
        saml: rustid_http::SamlState::default(),
    });
    Ok((state, saml))
}

/// The interaction settings. Messages in URLs (and, from sub-plan 2b,
/// session cookies) are sealed with the configured key ring, or with a
/// per-process key when none is configured.
fn interaction_state(config: &ServerConfig) -> anyhow::Result<InteractionState> {
    let mut interaction = InteractionState {
        api_keys: config.interaction.api_keys.clone(),
        supported_ui_cultures: config.localization.supported_ui_cultures.clone(),
        ..InteractionState::default()
    };
    match config.data_protector()? {
        Some(protector) => interaction.protector = Arc::new(protector),
        None => tracing::warn!(
            "data_protection.keys is not configured: interaction messages are sealed with a \
             per-process key and don't survive a restart or reach other instances"
        ),
    }
    Ok(interaction)
}

/// The automatic key manager, `None` when key management is disabled. Keys
/// live in the file system for the memory store and in Postgres otherwise.
async fn key_manager(
    config: &ServerConfig,
    pg: Option<PgStore>,
) -> anyhow::Result<Option<Arc<KeyManager>>> {
    let options = &config.protocol.key_management;
    if !options.enabled {
        return Ok(None);
    }
    let store: Arc<dyn SigningKeyStore> = match pg {
        Some(pg) => Arc::new(pg),
        None => Arc::new(FileSystemSigningKeyStore::new(options.key_path())),
    };
    let location = match &config.store.kind {
        StoreKind::Postgres => "the Postgres signing_keys table".to_owned(),
        StoreKind::Memory => options.key_path().display().to_string(),
    };
    tracing::info!(
        keys = %location,
        static_signing_keys = config.signing_keys.len(),
        "automatic key management is enabled (set protocol.key_management.enabled = false to use only static keys)"
    );
    // Stored keys are unprotected according to their own records, so the
    // ring is loaded whenever one exists; `data_protect_keys` only decides
    // how new keys are written (and whether a ring must exist).
    let protector = data_protector(config).await?.map(Arc::new);
    let subject = config
        .protocol
        .issuer_uri
        .clone()
        .unwrap_or_else(|| "OP".to_owned());
    Ok(Some(Arc::new(KeyManager::new(
        options.clone(),
        store,
        protector,
        Arc::new(SystemClock),
        &subject,
    ))))
}

/// The configured key ring. Without one: for the memory store, the local
/// key in `{key_path}/data-protection.key`, created when new keys will be
/// protected; for Postgres, an error when new keys will be protected.
async fn data_protector(config: &ServerConfig) -> anyhow::Result<Option<DataProtector>> {
    if let Some(protector) = config.data_protector()? {
        return Ok(Some(protector));
    }
    let protect = config.protocol.key_management.data_protect_keys;
    if config.store.kind == StoreKind::Postgres {
        if protect {
            anyhow::bail!(
                "data_protection.keys must be configured to protect signing keys stored in \
                 Postgres (or set protocol.key_management.data_protect_keys = false)"
            );
        }
        return Ok(None);
    }
    let path = config
        .protocol
        .key_management
        .key_path()
        .join("data-protection.key");
    if !protect && !tokio::fs::try_exists(&path).await.unwrap_or(false) {
        return Ok(None);
    }
    let secret = local_master_key(&path)
        .await
        .with_context(|| format!("data protection key file {}", path.display()))?;
    Ok(Some(DataProtector::new([("local", secret.as_slice())])?))
}

/// Reads the base64 key at `path`, creating it (owner-only) when missing.
async fn local_master_key(path: &Path) -> anyhow::Result<Vec<u8>> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    match tokio::fs::read_to_string(path).await {
        Ok(text) => Ok(STANDARD.decode(text.trim())?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use tokio::io::AsyncWriteExt;
            if let Some(dir) = path.parent() {
                tokio::fs::create_dir_all(dir).await?;
            }
            let secret = rustid_core::data_protection::generate_key();
            let mut options = tokio::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            match options.open(path).await {
                Ok(mut file) => {
                    file.write_all(STANDARD.encode(secret).as_bytes()).await?;
                    file.flush().await?;
                    tracing::warn!(
                        path = %path.display(),
                        "generated a data protection key; configure data_protection.keys for \
                         deployments with more than one instance"
                    );
                    Ok(secret.to_vec())
                }
                // Another process created it first: use theirs.
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    Ok(STANDARD.decode(tokio::fs::read_to_string(path).await?.trim())?)
                }
                Err(e) => Err(e.into()),
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// The stores, with the Postgres store or the memory configuration (seeded
/// with the SAML service providers) for the SAML stores.
async fn build_stores(
    config: &ServerConfig,
    saml_providers: &[rustid_saml::model::ServiceProvider],
) -> anyhow::Result<(
    Stores,
    Option<PgStore>,
    Option<Arc<rustid_store_memory::InMemoryConfiguration>>,
)> {
    match config.store.kind {
        StoreKind::Memory => {
            let resources = match &config.resources_file {
                Some(path) => Resources::load(path)?,
                None => Resources::default(),
            };
            let clients = match &config.clients_file {
                Some(path) => Clients::load(path)?,
                None => Clients::default(),
            };
            let configuration = Arc::new(
                rustid_store_memory::InMemoryConfiguration::new(&clients, &resources)
                    .with_saml_service_providers(saml_providers),
            );
            Ok((
                rustid_store_memory::stores_with(configuration.clone()),
                None,
                Some(configuration),
            ))
        }
        StoreKind::Postgres => {
            let pg = config
                .store
                .postgres
                .as_ref()
                .context("store.postgres is required for the postgres store")?;
            let store = open_postgres(pg).await?;
            // Validate the files exactly as the memory store loads them
            // (models, repeated properties, duplicate ids) before importing.
            if let Some(path) = &config.clients_file {
                Clients::load(path)?;
                let clients = read_json(path)?;
                let clients = clients
                    .as_array()
                    .with_context(|| format!("{} must hold a JSON array", path.display()))?;
                store
                    .import_clients(clients)
                    .await
                    .with_context(|| format!("importing {}", path.display()))?;
            }
            if let Some(path) = &config.resources_file {
                Resources::load(path)?;
                store
                    .import_resources(&read_json(path)?)
                    .await
                    .with_context(|| format!("importing {}", path.display()))?;
            }
            let caching = &config.protocol.caching;
            let seconds = |t: &rustid_core::options::TimeSpan| {
                Duration::from_secs(u64::try_from(t.0).unwrap_or(0))
            };
            let durations = CacheDurations {
                client_store: seconds(&caching.client_store_expiration),
                resource_store: seconds(&caching.resource_store_expiration),
                cors: seconds(&caching.cors_expiration),
            };
            let clients = Arc::new(CachingClientStore::new(store.clone(), durations));
            let resources = Arc::new(CachingResourceStore::new(store.clone(), durations));
            Ok((
                Stores {
                    clients: clients.clone(),
                    resources: resources.clone(),
                    configuration: Arc::new(configuration::InvalidatingConfiguration {
                        inner: store.clone(),
                        clients,
                        resources,
                    }),
                    grants: Arc::new(store.clone()),
                    device_flow: Arc::new(store.clone()),
                    device_throttling: Arc::new(store.clone()),
                    replay: Arc::new(store.clone()),
                    profile: Arc::new(rustid_core::profile::DefaultProfileService),
                    token_request: Arc::new(
                        rustid_core::token_request::DefaultTokenRequestValidator,
                    ),
                    request_uri: Arc::new(rustid_core::request_uri::NoRequestUriFetcher),
                    back_channel: Arc::new(rustid_core::logout::NoBackChannelSender),
                    grant_validation: Arc::new(rustid_core::grant_validation::NoGrantValidator),
                    ciba: Arc::new(rustid_core::ciba::NopCibaService),
                    sessions: None,
                    federation: Default::default(),
                },
                Some(store),
                None,
            ))
        }
    }
}

fn read_json(path: &Path) -> anyhow::Result<serde_json::Value> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Serves the application on `listener` until `shutdown` resolves.
pub async fn serve(
    listener: TcpListener,
    app: App,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let local = listener.local_addr()?;
    let cleanup = spawn_session_cleanup(app.state.clone());
    let purge = spawn_storage_purge(
        app.state.clone(),
        app.purge,
        app.saml.as_ref().map(|s| s.stores.clone()),
    );
    let outbox = spawn_outbox_processor(app.state.clone());
    let roots = app.trusted.client_ca_roots.clone();
    let router = router(&app, local);
    match app.tls {
        Some(tls) => {
            let router = router.layer(axum::Extension(rustid_http::Https));
            // `tap_io` gives the listener axum's `ConnectInfo` support.
            // Each connection's router carries its peer address and the
            // client certificate its handshake presented.
            let make = tower::service_fn(
                move |incoming: axum::serve::IncomingStream<'_, tls::TlsListener>| {
                    let remote = *incoming.remote_addr();
                    let certificate = tls::peer_certificate(incoming.io(), roots.as_deref());
                    let mut router = router
                        .clone()
                        .layer(axum::Extension(axum::extract::ConnectInfo(remote)));
                    if let Some(certificate) = certificate {
                        router = router.layer(axum::Extension(rustid_http::TlsClientCertificate(
                            std::sync::Arc::new(certificate),
                        )));
                    }
                    std::future::ready(Ok::<_, std::convert::Infallible>(router))
                },
            );
            axum::serve(tls::TlsListener::new(listener, tls)?, make)
                .with_graceful_shutdown(shutdown)
                .await?;
        }
        None => {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown)
            .await?;
        }
    }
    if let Some(cleanup) = cleanup {
        cleanup.abort();
    }
    for job in [purge, outbox].into_iter().flatten() {
        job.abort();
    }
    Ok(())
}

/// The application's router as `serve` serves it, before the listener's
/// per-connection layers (TLS, the peer address, the client certificate).
/// The background jobs aren't started; `serve` starts them.
pub fn router(app: &App, local: std::net::SocketAddr) -> axum::Router {
    // The reference UI calls the interaction API through the protocol
    // router itself. Its pages go through the session middleware too,
    // since they need the session.
    let ui = app
        .reference_ui
        .clone()
        .map(|ui| ui.routes(rustid_http::app(app.state.clone(), None)));
    let admin = app.admin.clone().map(rustid_admin::router);
    let extra = match (ui, admin) {
        (Some(ui), Some(admin)) => Some(ui.merge(admin)),
        (ui, admin) => ui.or(admin),
    };
    let router = rustid_http::app(app.state.clone(), extra);
    // Inside the listener's own layers, so a trusted proxy's scheme wins.
    let router = if app.trusted.proxies.is_empty() {
        router
    } else {
        router.layer(axum::middleware::from_fn_with_state(
            app.trusted.clone(),
            forwarded::apply,
        ))
    };
    router.layer(axum::Extension(rustid_http::LocalAddr(local)))
}

/// Connects to Postgres and applies pending migrations when configured.
pub(crate) async fn open_postgres(pg: &config::PostgresConfig) -> anyhow::Result<PgStore> {
    let store = PgStore::connect(&pg.url, pg.max_connections, pg.create_database)
        .await
        .context("connecting to Postgres")?;
    if pg.run_migrations {
        store.migrate().await?;
    }
    Ok(store)
}

/// A random delay below `seconds`, for fuzzed job starts.
fn fuzzed(seconds: u64) -> Duration {
    let random = rustid_core::data_protection::generate_key();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&random[..8]);
    Duration::from_secs(u64::from_le_bytes(bytes) % seconds.max(1))
}

/// Every `purge_interval` (at least a second, the first
/// run after a random part of it when fuzzing), removes expired grants,
/// device codes, and replay and throttling entries, in batches.
fn spawn_storage_purge(
    state: AppState,
    consumed: PurgeConsumed,
    saml: Option<rustid_saml::stores::SamlStores>,
) -> Option<tokio::task::JoinHandle<()>> {
    let options = state.0.options.storage_purge.clone();
    if !options.enable_purge {
        return None;
    }
    let seconds = u64::try_from(options.purge_interval.0).unwrap_or(1).max(1);
    let interval = Duration::from_secs(seconds);
    let mut delay = if options.fuzz_startup {
        fuzzed(seconds)
    } else {
        interval
    };
    let settings = rustid_core::purge::PurgeSettings {
        batch: usize::try_from(options.batch_size).unwrap_or(1),
        remove_consumed: consumed.remove,
        consumed_delay: consumed.delay,
    };
    Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(delay).await;
            delay = interval;
            let now = chrono::Utc::now();
            match rustid_core::purge::run(&state.0.stores, &settings, now).await {
                Ok(purged) => tracing::debug!(?purged, "storage purge"),
                Err(error) => tracing::error!(%error, "the storage purge failed"),
            }
            if let Some(saml) = &saml {
                match rustid_saml::stores::purge(saml, now, settings.batch).await {
                    Ok(removed) => tracing::debug!(removed, "SAML storage purge"),
                    Err(error) => tracing::error!(%error, "the SAML storage purge failed"),
                }
            }
        }
    }))
}

/// With server-side sessions and
/// `remove_expired_sessions`, removes and processes expired sessions every
/// `remove_expired_sessions_frequency`, the first run after a random part
/// of it when fuzzing.
fn spawn_session_cleanup(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    let options = &state.0.options.server_side_sessions;
    if state.0.stores.sessions.is_none() || !options.remove_expired_sessions {
        return None;
    }
    let seconds = u64::try_from(options.remove_expired_sessions_frequency.0)
        .unwrap_or(1)
        .max(1);
    let frequency = Duration::from_secs(seconds);
    let mut delay = if options.fuzz_expired_session_removal_start {
        fuzzed(seconds)
    } else {
        frequency
    };
    Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(delay).await;
            delay = frequency;
            let state = &state.0;
            let issuer = state.options.issuer_uri.clone().unwrap_or_default();
            let ctx = rustid_core::access_tokens::ValidationContext {
                options: &state.options,
                stores: &state.stores,
                keys: &state.keys,
                issuer: &issuer,
                now: chrono::Utc::now(),
            };
            match rustid_core::server_side_sessions::expire_sessions(&ctx).await {
                Ok(0) => {}
                Ok(moved) => {
                    tracing::info!(moved, "moved expired server-side sessions to the outbox")
                }
                Err(error) => tracing::error!(%error, "expiring sessions failed"),
            }
        }
    }))
}

/// With server-side sessions and `enable_processor`,
/// processes due outbox events every `process_interval` (at least a
/// second, the first run after a random part of it when fuzzing).
fn spawn_outbox_processor(state: AppState) -> Option<tokio::task::JoinHandle<()>> {
    let options = state.0.options.outbox_processor.clone();
    if state.0.stores.sessions.is_none() || !options.enable_processor {
        return None;
    }
    let seconds = u64::try_from(options.process_interval.0)
        .unwrap_or(1)
        .max(1);
    let interval = Duration::from_secs(seconds);
    let mut delay = if options.fuzz_startup {
        fuzzed(seconds)
    } else {
        interval
    };
    Some(tokio::spawn(async move {
        loop {
            tokio::time::sleep(delay).await;
            delay = interval;
            let state = &state.0;
            let issuer = state.options.issuer_uri.clone().unwrap_or_default();
            let ctx = rustid_core::access_tokens::ValidationContext {
                options: &state.options,
                stores: &state.stores,
                keys: &state.keys,
                issuer: &issuer,
                now: chrono::Utc::now(),
            };
            match rustid_core::outbox::process(&ctx).await {
                Ok(processed) if processed == Default::default() => {}
                Ok(processed) => tracing::info!(?processed, "processed outbox events"),
                Err(error) => tracing::error!(%error, "processing the outbox failed"),
            }
        }
    }))
}

/// The schemas in `path` become the
/// registered set. Each is created, or updated where it differs, and stored
/// schemas the file doesn't list are removed, so a restart applies an edited
/// file.
pub async fn register_schemas(
    store: &dyn rustid_core::stores::ConfigurationStore,
    path: &std::path::Path,
) -> anyhow::Result<()> {
    use rustid_core::admin::schemas::{SchemaAdmin, SchemaConfiguration};
    let context = || format!("admin.schemas_file {}", path.display());
    let text = std::fs::read_to_string(path).with_context(context)?;
    let schemas: Vec<SchemaConfiguration> = serde_json::from_str(&text).with_context(context)?;
    let listed: Vec<String> = schemas
        .iter()
        .map(|s| s.schema_id.to_ascii_lowercase())
        .collect();
    for stored in SchemaAdmin.query(store).await? {
        if !listed.contains(&stored.schema_id.to_ascii_lowercase()) {
            tracing::info!(schema = %stored.schema_id, "removing a schema schemas_file no longer lists");
            let _ = SchemaAdmin.delete(store, &stored.schema_id).await?;
        }
    }
    for schema in schemas {
        let id = schema.schema_id.clone();
        let result = match SchemaAdmin.get(store, &id).await? {
            None => SchemaAdmin.create(store, schema).await?,
            Some(existing) if existing.item == schema => continue,
            Some(existing) => {
                SchemaAdmin
                    .update(store, &id, schema, existing.version)
                    .await?
            }
        };
        if let Err(errors) = result {
            let messages: Vec<&str> = errors.iter().map(|e| e.message.as_str()).collect();
            anyhow::bail!("{}: schema '{id}': {}", context(), messages.join(" "));
        }
    }
    Ok(())
}
