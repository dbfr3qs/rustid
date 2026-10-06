// figment::Jail closures must return figment::Error, which trips this lint.
#![allow(clippy::result_large_err)]

use std::net::SocketAddr;
use std::path::Path;

use rustid_core::options::TimeSpan;
use rustid_server::config::{ConfigError, LogFormat, PostgresConfig, ServerConfig, StoreKind};

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
fn empty_file_gives_defaults_and_a_dynamic_issuer() {
    figment::Jail::expect_with(|jail| {
        jail.create_file("rustid.toml", "")?;
        let cfg = ServerConfig::load(Some(Path::new("rustid.toml"))).unwrap();
        assert_eq!(cfg.protocol.issuer_uri, None);
        assert_eq!(cfg.listen, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.log.format, LogFormat::Pretty);
        assert_eq!(cfg.log.level, "info");
        assert!(cfg.signing_keys.is_empty());
        assert_eq!(cfg.path_base, None);
        Ok(())
    });
}

#[test]
fn environment_overrides_file_values() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "rustid.toml",
            r#"
listen = "127.0.0.1:1"

[log]
level = "warn"

[protocol]
issuer_uri = "https://from-file.test"
"#,
        )?;
        jail.set_env("RUSTID_LISTEN", "0.0.0.0:9090");
        jail.set_env("RUSTID_LOG__LEVEL", "debug");
        jail.set_env("RUSTID_LOG__FORMAT", "json");
        jail.set_env("RUSTID_PROTOCOL__ISSUER_URI", "https://from-env.test");
        let cfg = ServerConfig::load(Some(Path::new("rustid.toml"))).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:9090".parse::<SocketAddr>().unwrap());
        assert_eq!(cfg.log.level, "debug");
        assert_eq!(cfg.log.format, LogFormat::Json);
        assert_eq!(
            cfg.protocol.issuer_uri.as_deref(),
            Some("https://from-env.test")
        );
        Ok(())
    });
}

#[test]
fn loads_from_environment_alone_when_no_file_is_given() {
    figment::Jail::expect_with(|jail| {
        jail.set_env("RUSTID_PROTOCOL__ISSUER_URI", "https://idsrv.test");
        let cfg = ServerConfig::load(None).unwrap();
        assert_eq!(
            cfg.protocol.issuer_uri.as_deref(),
            Some("https://idsrv.test")
        );
        Ok(())
    });
}

#[test]
fn json_file_is_read_and_relative_paths_resolve_against_its_directory() {
    figment::Jail::expect_with(|jail| {
        std::fs::create_dir("profiles").unwrap();
        jail.create_file(
            "profiles/p.json",
            r#"{ "resources_file": "../resources.json",
                 "signing_keys": [ { "kid": "k", "alg": "RS256", "key_file": "../key.pem", "cert_file": "/abs/cert.pem" } ] }"#,
        )?;
        let cfg = ServerConfig::load(Some(Path::new("profiles/p.json"))).unwrap();
        assert_eq!(
            cfg.resources_file.unwrap(),
            Path::new("profiles/../resources.json")
        );
        assert_eq!(
            cfg.signing_keys[0].key_file,
            Path::new("profiles/../key.pem")
        );
        assert_eq!(
            cfg.signing_keys[0].cert_file.as_deref(),
            Some(Path::new("/abs/cert.pem"))
        );
        Ok(())
    });
}

#[test]
fn create_account_url_is_finalized_into_prompt_values() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "c.json",
            r#"{ "protocol": { "user_interaction": { "create_account_url": "/x" } } }"#,
        )?;
        let cfg = ServerConfig::load(Some(Path::new("c.json"))).unwrap();
        assert_eq!(
            cfg.protocol
                .user_interaction
                .prompt_values_supported
                .last()
                .unwrap(),
            "create"
        );
        Ok(())
    });
}

#[test]
fn issuer_with_query_or_fragment_or_non_http_scheme_is_rejected() {
    for issuer in [
        "https://idsrv.test/?x=1",
        "https://idsrv.test/#f",
        "ftp://idsrv.test",
        "not a url",
    ] {
        figment::Jail::expect_with(|jail| {
            jail.create_file(
                "rustid.toml",
                &format!("[protocol]\nissuer_uri = \"{issuer}\""),
            )?;
            let err = ServerConfig::load(Some(Path::new("rustid.toml"))).unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidIssuer(_)),
                "{issuer}: got {err:?}"
            );
            Ok(())
        });
    }
}

#[test]
fn path_base_must_start_with_slash_and_not_end_with_one() {
    for base in ["root", "/root/", "/"] {
        figment::Jail::expect_with(|jail| {
            jail.create_file("rustid.toml", &format!("path_base = \"{base}\""))?;
            let err = ServerConfig::load(Some(Path::new("rustid.toml"))).unwrap_err();
            assert!(
                matches!(err, ConfigError::InvalidPathBase(_)),
                "{base}: got {err:?}"
            );
            Ok(())
        });
    }
}

#[test]
fn unknown_protocol_option_names_the_key() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "rustid.toml",
            "[protocol.endpoints]\nenable_tokn_endpoint = false",
        )?;
        let err = ServerConfig::load(Some(Path::new("rustid.toml"))).unwrap_err();
        assert!(
            err.to_string().contains("enable_tokn_endpoint"),
            "message was: {err}"
        );
        Ok(())
    });
}

#[test]
fn env_override_with_invalid_listen_names_the_key() {
    figment::Jail::expect_with(|jail| {
        jail.create_file("rustid.toml", "")?;
        jail.set_env("RUSTID_LISTEN", "not-an-address");
        let err = ServerConfig::load(Some(Path::new("rustid.toml"))).unwrap_err();
        assert!(err.to_string().contains("listen"), "message was: {err}");
        Ok(())
    });
}

#[test]
fn nonexistent_config_file_names_the_path() {
    figment::Jail::expect_with(|jail| {
        jail.set_env("RUSTID_LOG__LEVEL", "info");
        let err = ServerConfig::load(Some(Path::new("does-not-exist.toml"))).unwrap_err();
        assert!(matches!(err, ConfigError::MissingFile(_)), "got {err:?}");
        assert!(
            err.to_string().contains("does-not-exist.toml"),
            "message was: {err}"
        );
        Ok(())
    });
}

#[test]
fn every_committed_profile_loads_and_builds_state() {
    // Inside a Jail so no other test's RUSTID_ variables leak into the load.
    figment::Jail::expect_with(|_| {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/profiles");
        let mut count = 0;
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let cfg = ServerConfig::load(Some(&path))
                .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            build(&cfg).unwrap_or_else(|e| panic!("{}: {e:#}", path.display()));
            count += 1;
        }
        assert!(
            count >= 7,
            "expected the seven phase 1a profiles, found {count}"
        );
        Ok(())
    });
}

#[test]
fn build_state_fails_naming_the_key_when_a_key_file_is_missing() {
    figment::Jail::expect_with(|jail| {
        jail.create_file("k.json", r#"{ "signing_keys": [ { "kid": "lost", "alg": "RS256", "key_file": "missing.pem" } ] }"#)?;
        let cfg = ServerConfig::load(Some(Path::new("k.json"))).unwrap();
        let err = format!("{:#}", build(&cfg).unwrap_err());
        assert!(
            err.contains("lost") && err.contains("missing.pem"),
            "message was: {err}"
        );
        Ok(())
    });
}

#[test]
fn unknown_top_level_key_names_the_key() {
    figment::Jail::expect_with(|jail| {
        jail.create_file("p.json", r#"{ "path_bse": "/typo" }"#)?;
        let err = ServerConfig::load(Some(Path::new("p.json"))).unwrap_err();
        assert!(err.to_string().contains("path_bse"), "message was: {err}");
        Ok(())
    });
}

#[test]
fn clients_file_is_accepted_and_config_env_is_ignored() {
    figment::Jail::expect_with(|jail| {
        jail.create_file("p.json", r#"{ "clients_file": "clients.json" }"#)?;
        // clap reads RUSTID_CONFIG itself; it must not be treated as a config key.
        jail.set_env("RUSTID_CONFIG", "p.json");
        let cfg = ServerConfig::load(Some(Path::new("p.json"))).unwrap();
        assert_eq!(cfg.clients_file.as_deref(), Some(Path::new("clients.json")));
        Ok(())
    });
}

#[test]
fn the_store_defaults_to_memory() {
    figment::Jail::expect_with(|jail| {
        jail.create_file("rustid.toml", "")?;
        let cfg = ServerConfig::load(Some(Path::new("rustid.toml"))).unwrap();
        assert_eq!(cfg.store.kind, StoreKind::Memory);
        assert_eq!(cfg.store.postgres, None);
        assert_eq!(cfg.protocol.caching.client_store_expiration, TimeSpan(900));
        Ok(())
    });
}

#[test]
fn the_postgres_store_is_configured_from_the_environment() {
    figment::Jail::expect_with(|jail| {
        jail.set_env("RUSTID_STORE__KIND", "postgres");
        jail.set_env("RUSTID_STORE__POSTGRES__URL", "postgres://db/rustid");
        jail.set_env("RUSTID_PROTOCOL__CACHING__CORS_EXPIRATION", "00:01:00");
        let cfg = ServerConfig::load(None).unwrap();
        assert_eq!(cfg.store.kind, StoreKind::Postgres);
        assert_eq!(
            cfg.store.postgres,
            Some(PostgresConfig {
                url: "postgres://db/rustid".into(),
                max_connections: 10,
                create_database: false,
                run_migrations: true,
            })
        );
        assert_eq!(cfg.protocol.caching.cors_expiration, TimeSpan(60));
        Ok(())
    });
}

#[test]
fn store_kind_and_postgres_section_must_agree() {
    figment::Jail::expect_with(|jail| {
        jail.create_file("pg.toml", "[store]\nkind = \"postgres\"\n")?;
        assert!(matches!(
            ServerConfig::load(Some(Path::new("pg.toml"))),
            Err(ConfigError::MissingPostgres)
        ));
        jail.create_file("mem.toml", "[store.postgres]\nurl = \"postgres://db/x\"\n")?;
        assert!(matches!(
            ServerConfig::load(Some(Path::new("mem.toml"))),
            Err(ConfigError::UnusedPostgres)
        ));
        jail.create_file("bad.toml", "[store]\nkind = \"redis\"\n")?;
        let err = ServerConfig::load(Some(Path::new("bad.toml"))).unwrap_err();
        assert!(err.to_string().contains("store.kind"), "{err}");
        Ok(())
    });
}

#[test]
fn a_postgres_pool_needs_at_least_one_connection() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "pg.toml",
            "[store]\nkind = \"postgres\"\n[store.postgres]\nurl = \"postgres://db/x\"\nmax_connections = 0\n",
        )?;
        let err = ServerConfig::load(Some(Path::new("pg.toml"))).unwrap_err();
        assert!(err.to_string().contains("max_connections"), "{err}");
        Ok(())
    });
}

#[test]
fn key_management_and_data_protection_are_validated() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "km.toml",
            "[protocol.key_management]\nrotation_interval = \"10.00:00:00\"\n",
        )?;
        let err = ServerConfig::load(Some(Path::new("km.toml"))).unwrap_err();
        assert!(matches!(err, ConfigError::KeyManagement(_)), "{err}");
        assert!(
            err.to_string().contains("longer than propagation_time"),
            "{err}"
        );

        for secret in ["not base64!", "AAAA"] {
            jail.create_file(
                "dp.toml",
                &format!("[[data_protection.keys]]\nid = \"k1\"\nsecret = \"{secret}\"\n"),
            )?;
            let err = ServerConfig::load(Some(Path::new("dp.toml"))).unwrap_err();
            assert!(
                matches!(err, ConfigError::DataProtection(_)),
                "{secret}: {err}"
            );
        }
        jail.create_file(
            "ok.toml",
            "[[data_protection.keys]]\nid = \"k1\"\nsecret = \"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\"\n",
        )?;
        let cfg = ServerConfig::load(Some(Path::new("ok.toml"))).unwrap();
        assert!(cfg.data_protector().unwrap().is_some());
        assert!(
            !format!("{:?}", cfg.data_protection).contains("AQEB"),
            "secrets are redacted in debug output"
        );
        Ok(())
    });
}

#[test]
fn key_path_is_relative_to_the_config_file() {
    figment::Jail::expect_with(|jail| {
        jail.create_dir("conf")?;
        jail.create_file(
            "conf/rustid.toml",
            "[protocol.key_management]\nkey_path = \"signing\"\n",
        )?;
        let cfg = ServerConfig::load(Some(Path::new("conf/rustid.toml"))).unwrap();
        assert_eq!(
            cfg.protocol.key_management.key_path(),
            Path::new("conf").join("signing")
        );
        assert!(cfg.protocol.key_management.enabled, "on by default");
        Ok(())
    });
}

#[test]
fn an_unset_key_path_is_keys_in_the_working_directory() {
    figment::Jail::expect_with(|jail| {
        jail.create_dir("etc")?;
        jail.create_file("etc/rustid.toml", "")?;
        let cfg = ServerConfig::load(Some(Path::new("etc/rustid.toml"))).unwrap();
        assert_eq!(
            cfg.protocol.key_management.key_path(),
            Path::new("keys"),
            "not next to a possibly read-only configuration file"
        );
        Ok(())
    });
}

#[test]
fn telemetry_and_events_are_configurable() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "t.toml",
            r#"
[protocol.events]
raise_failure_events = true

[telemetry]
service_name = "idp"
metrics_interval = "00:00:15"

[telemetry.otlp]
endpoint = "http://collector:4318"
headers = { "x-api-key" = "secret-key" }
"#,
        )?;
        let cfg = ServerConfig::load(Some(Path::new("t.toml"))).unwrap();
        assert!(cfg.protocol.events.raise_failure_events);
        assert!(!cfg.protocol.events.raise_success_events);
        assert_eq!(cfg.telemetry.service_name, "idp");
        assert_eq!(cfg.telemetry.metrics_interval, TimeSpan(15));
        let otlp = cfg.telemetry.otlp.clone().unwrap();
        assert_eq!(otlp.endpoint, "http://collector:4318");
        assert!(
            !format!("{otlp:?}").contains("secret-key"),
            "header values are redacted"
        );

        jail.create_file(
            "bad.toml",
            "[telemetry.otlp]\nendpoint = \"collector:4318\"\n",
        )?;
        let err = ServerConfig::load(Some(Path::new("bad.toml"))).unwrap_err();
        assert!(matches!(err, ConfigError::Telemetry(_)), "{err}");
        jail.create_file("zero.toml", "[telemetry]\nmetrics_interval = 0\n")?;
        let err = ServerConfig::load(Some(Path::new("zero.toml"))).unwrap_err();
        assert!(matches!(err, ConfigError::Telemetry(_)), "{err}");
        Ok(())
    });
}

#[test]
fn interaction_localization_and_reference_ui_are_configurable() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "ui.toml",
            r#"
[localization]
supported_ui_cultures = ["en-US", "nb-NO"]
[interaction]
api_keys = ["0123456789abcdef-key"]
[reference_ui]
enabled = true
"#,
        )?;
        let cfg = ServerConfig::load(Some(Path::new("ui.toml"))).unwrap();
        assert_eq!(cfg.localization.supported_ui_cultures, ["en-US", "nb-NO"]);
        assert!(cfg.reference_ui.enabled);
        assert!(
            !format!("{:?}", cfg.interaction).contains("0123456789"),
            "API keys are redacted in debug output"
        );
        let state = build(&cfg).unwrap();
        assert_eq!(state.0.interaction.api_keys, ["0123456789abcdef-key"]);
        assert_eq!(
            state.0.interaction.supported_ui_cultures,
            ["en-US", "nb-NO"]
        );

        jail.create_file("weak.toml", "[interaction]\napi_keys = [\"short\"]\n")?;
        let err = ServerConfig::load(Some(Path::new("weak.toml"))).unwrap_err();
        assert!(matches!(err, ConfigError::WeakApiKey), "{err}");

        let defaults = ServerConfig::load(None).unwrap();
        assert!(
            !defaults.reference_ui.enabled,
            "the reference UI is off by default"
        );
        assert!(defaults.interaction.api_keys.is_empty());
        Ok(())
    });
}

#[test]
fn reference_ui_users_file_resolves_against_the_config_file() {
    figment::Jail::expect_with(|jail| {
        jail.create_dir("conf")?;
        jail.create_file(
            "conf/rustid.toml",
            "[reference_ui]\nenabled = true\nusers_file = \"users.json\"\n",
        )?;
        let cfg = ServerConfig::load(Some(Path::new("conf/rustid.toml"))).unwrap();
        assert_eq!(
            cfg.reference_ui.users_file.as_deref(),
            Some(Path::new("conf").join("users.json").as_path())
        );
        assert_eq!(cfg.reference_ui.default_user, "alice");
        Ok(())
    });
}

#[test]
fn a_forwarded_certificate_header_needs_trusted_proxies() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "untrusted.toml",
            "[mutual_tls]\nforwarded_certificate_header = \"X-Client-Cert\"\n",
        )?;
        assert!(matches!(
            ServerConfig::load(Some(Path::new("untrusted.toml"))),
            Err(ConfigError::UntrustedCertificateHeader)
        ));
        jail.create_file(
            "trusted.toml",
            "[mutual_tls]\nforwarded_certificate_header = \"X-Client-Cert\"\n\
             [forwarded_headers]\ntrusted_proxies = [\"127.0.0.1\"]\n",
        )?;
        assert!(ServerConfig::load(Some(Path::new("trusted.toml"))).is_ok());
        Ok(())
    });
}

#[test]
fn jarm_lifetime_must_be_positive() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "rustid.toml",
            "[protocol.jarm]\nenabled = true\nlifetime = 0\n",
        )?;
        let cfg = ServerConfig::load(Some(Path::new("rustid.toml"))).unwrap();
        let error = format!(
            "{:#}",
            match build(&cfg) {
                Err(e) => e,
                Ok(_) => panic!("refused"),
            }
        );
        assert!(error.contains("jarm.lifetime"), "{error}");
        Ok(())
    });
}

/// Each setting that would silently do nothing is named at startup; the
/// defaults name none.
#[test]
fn config_warnings_name_each_silent_misconfiguration() {
    figment::Jail::expect_with(|jail| {
        let key = rcgen::KeyPair::generate().unwrap(); // ECDSA P-256
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        jail.create_file("cert.pem", &cert.pem())?;
        jail.create_file("key.pem", &key.serialize_pem())?;
        let warnings = |toml: &str| {
            jail.create_file("rustid.toml", toml).unwrap();
            let cfg = ServerConfig::load(Some(Path::new("rustid.toml"))).unwrap();
            rustid_server::config_warnings(&cfg)
        };
        assert!(warnings("").is_empty());
        let cases = [
            (
                "[admin]\nschemas_file = \"schemas.json\"\n",
                "admin.schemas_file",
            ),
            (
                "[server_side_sessions]\nenabled = true\n[protocol.outbox_processor]\nenable_processor = false\n",
                "enable_processor",
            ),
            (
                "[tls]\ncert_file = \"cert.pem\"\nkey_file = \"key.pem\"\ncipher_suites = \"fapi\"\n",
                "cipher_suites",
            ),
            (
                "[dynamic_client_registration]\nenabled = true\nopen = true\npath = \"/register\"\n[protocol.discovery.dynamic_client_registration]\nregistration_endpoint_mode = \"Inferred\"\n",
                "/register",
            ),
            (
                "[protocol.discovery.dynamic_client_registration]\nregistration_endpoint_mode = \"Inferred\"\n",
                "dynamic_client_registration is off",
            ),
        ];
        for (toml, key) in cases {
            let found = warnings(toml);
            assert_eq!(found.len(), 1, "{toml}: {found:?}");
            assert!(found[0].contains(key), "{toml}: {found:?}");
        }
        Ok(())
    });
}

#[test]
fn an_unknown_section_is_refused() {
    figment::Jail::expect_with(|jail| {
        jail.create_file("rustid.toml", "[no_such_section]\nusers_file = \"x\"\n")?;
        let error = ServerConfig::load(Some(Path::new("rustid.toml")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unknown field"), "{error}");
        Ok(())
    });
}

#[test]
fn the_protocol_section_configures_the_protocol() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "rustid.toml",
            "[protocol]\nissuer_uri = \"https://idp.test\"\n",
        )?;
        let cfg = ServerConfig::load(Some(Path::new("rustid.toml"))).unwrap();
        assert_eq!(cfg.protocol.issuer_uri.as_deref(), Some("https://idp.test"));
        Ok(())
    });
}

#[test]
fn the_old_identity_server_section_is_refused_with_a_hint() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "rustid.toml",
            "[identity_server]\nissuer_uri = \"https://idp.test\"\n",
        )?;
        let error = ServerConfig::load(Some(Path::new("rustid.toml")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("[protocol]"), "{error}");
        Ok(())
    });
}

#[test]
fn the_old_environment_prefix_is_refused_with_a_hint() {
    figment::Jail::expect_with(|jail| {
        jail.create_file("rustid.toml", "")?;
        jail.set_env("RUSTID_IDENTITY_SERVER__ISSUER_URI", "https://idp.test");
        let error = ServerConfig::load(Some(Path::new("rustid.toml")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("RUSTID_PROTOCOL__"), "{error}");
        Ok(())
    });
}

#[test]
fn the_old_section_is_refused_in_json_configs_too() {
    figment::Jail::expect_with(|jail| {
        jail.create_file(
            "rustid.json",
            r#"{ "identity_server": { "endpoints": {} } }"#,
        )?;
        let error = ServerConfig::load(Some(Path::new("rustid.json")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("[protocol]"), "{error}");
        Ok(())
    });
}

#[test]
fn the_old_environment_prefix_is_refused_in_any_case() {
    figment::Jail::expect_with(|jail| {
        jail.create_file("rustid.toml", "")?;
        jail.set_env("rustid_identity_server__issuer_uri", "https://idp.test");
        let error = ServerConfig::load(Some(Path::new("rustid.toml")))
            .unwrap_err()
            .to_string();
        assert!(error.contains("RUSTID_PROTOCOL__"), "{error}");
        Ok(())
    });
}

#[test]
fn outbox_delays_must_be_sensible() {
    figment::Jail::expect_with(|jail| {
        for (name, body) in [
            (
                "negative.toml",
                "[protocol.outbox_processor]\nretry_delay = -5\n",
            ),
            (
                "huge.toml",
                "[protocol.outbox_processor]\nmax_retry_delay = 9223372036854775807\n",
            ),
            (
                "zero.toml",
                "[protocol.outbox_processor]\nprocess_interval = 0\n",
            ),
        ] {
            jail.create_file(name, body)?;
            let err = ServerConfig::load(Some(Path::new(name))).unwrap_err();
            assert!(
                err.to_string().contains("protocol.outbox_processor"),
                "{name}: {err}"
            );
        }
        Ok(())
    });
}

#[test]
fn the_protected_resource_path_must_be_a_path() {
    figment::Jail::expect_with(|jail| {
        for path in [
            "fapi2/resource",
            "/fapi2/resource?x=1",
            "https://x/resource",
        ] {
            jail.create_file(
                "r.toml",
                &format!("[protected_resource]\npath = \"{path}\"\n"),
            )?;
            let err = ServerConfig::load(Some(Path::new("r.toml"))).unwrap_err();
            assert!(
                err.to_string().contains("protected_resource.path"),
                "{path}: {err}"
            );
        }
        Ok(())
    });
}
