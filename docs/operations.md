# Operating rustid

This guide covers running `rustid-server` in a deployment. Every setting named here is in [`examples/rustid.toml`](../examples/rustid.toml), the configuration reference, with its default. A test (`crates/rustid-server/tests/config_reference.rs`) fails when a setting is missing from it.

## Running

```
rustid-server --config rustid.toml                 # serve
rustid-server --config rustid.toml import b.json   # import a migration bundle, then exit (docs/migration.md)
rustid-server --probe http://127.0.0.1:8080/ready  # exit 0 when the URL answers 2xx, 1 otherwise
```

- **Configuration file:** `--config` (or `RUSTID_CONFIG`) names a TOML file, or JSON when the extension is `.json`. Relative paths inside it are resolved against its directory.
- **Environment overrides:** `RUSTID_*` variables override the file, with `__` between nesting levels: `RUSTID_LISTEN=0.0.0.0:8080`, `RUSTID_PROTOCOL__ISSUER_URI=https://id.example.com`.
- **Strict keys:** every section rejects unknown keys, so a misspelt setting stops the server at start.
- **Without a file:** the server starts on `127.0.0.1:8080` with the memory store and automatic key management.

### Container

`docker build -t rustid .` builds a static binary on `scratch`. It runs as uid 65532, listens on port 8080 (`RUSTID_LISTEN=0.0.0.0:8080`), and works in `/var/lib/rustid`, where key management keeps its keys and the generated data protection key. Mount a volume there, or configure `[[data_protection.keys]]` and the Postgres store.

The image's `HEALTHCHECK` runs `rustid-server --probe http://127.0.0.1:8080/ready`. If you change the port, or serve TLS on it, override the health check. The probe ignores `HTTP_PROXY` and doesn't follow redirects. `scripts/container-check.sh` builds the image and checks it, and CI runs it.

Outgoing HTTPS (hooks, back-channel logout, request URIs) trusts the built-in Mozilla roots and the system's. In the image the system's are `/etc/ssl/certs/ca-certificates.crt`: mount a corporate bundle there, or point `SSL_CERT_FILE` at one.

## Listeners and proxies

- **HTTP** by default.
- **TLS:** `[tls]` serves HTTPS on `listen` from a PEM chain (leaf first) and a key (PKCS#8, PKCS#1 or SEC1). `cipher_suites = "fapi"` limits TLS 1.2 to the FAPI 2.0 suites. Browsers keep the session cookies only over HTTPS: they are `SameSite=None; Secure`.
- **mTLS:** `tls.client_certificates = "request"` asks clients for a certificate without requiring one. `[protocol.mutual_tls]` enables certificate client authentication (`X509Thumbprint` and `X509Name` secrets) and certificate-bound tokens, under `/connect/mtls/*` or a separate `domain_name`. The mTLS token endpoint is then also accepted as a client assertion's audience. A client with `requireCertificateBoundTokens` must present a certificate at the token endpoint and send no DPoP proof, and the tokens it gets there are bound to the certificate. `X509Name` secrets match only certificates that chain to `[mutual_tls] client_ca_file`.
- **Behind a reverse proxy:** list the proxy in `[forwarded_headers] trusted_proxies` (addresses or CIDR networks). Its `X-Forwarded-Proto`, `X-Forwarded-Host` and `X-Forwarded-For` (the rightmost value of each) then set the scheme, host and client address, so URLs, the issuer and `Secure` cookies follow what the proxy saw. Anyone else's forwarded headers are ignored.
  - With mTLS behind a proxy that terminates TLS, `[mutual_tls] forwarded_certificate_header` names the header carrying the client certificate (URL-encoded PEM, PEM or base64 DER). Only a trusted proxy may set it, and the certificate a trusted proxy itself presents is then ignored. Without the header, the certificate of the TLS connection counts, whoever presents it: right for a proxy that passes TLS through, but a proxy that terminates TLS and connects with a client certificate of its own should have the header configured.
  - `X-Forwarded-Prefix` and RFC 7239 `Forwarded` aren't read: set `path_base` instead.
- **Issuer:** set `protocol.issuer_uri` when the server is reached under several names, or when hooks check the `iss` of the JWTs it signs. Otherwise the issuer of tokens comes from the request, and hook JWTs carry `iss: "rustid"`.
- **Signed authorization responses (JARM):** `[protocol.jarm] enabled = true` accepts `response_mode=jwt`, `query.jwt`, `fragment.jwt` and `form_post.jwt`. The response parameters (errors included) then arrive as one JWT, `response`, signed with the key the client's id tokens use, for the client as audience and valid for `lifetime` seconds. Discovery advertises the modes and `authorization_signing_alg_values_supported`. It is off by default. FAPI 2 Message Signing also wants request objects limited in lifetime: set `request_object_max_lifetime = "01:00:00"` (see `conformance/fapi2-ms/rustid.toml`).

## Stores

`[store] kind` is `memory` (the default) or `postgres`.

- **Memory:**
  - clients come from `clients_file`, resources from `resources_file`, and SAML service providers from `[saml] service_providers_file`;
  - grants, sessions and the replay cache live in process memory, and are lost on restart and not shared;
  - one instance only;
  - admin API writes reach the runtime at once, and are lost on restart.
- **Postgres** (`[store.postgres]`):
  - migrations run at start (`run_migrations = true`), and `create_database = true` creates the database (a development convenience);
  - the configuration files, when set, are upserted at every start and overwrite the entities they define, admin edits included. Entities created through the admin API that aren't in the files are kept. Manage an entity in the file or through the admin API, not both;
  - client and resource lookups are cached (`[protocol.caching]`, 15 minutes by default). On another instance, an admin write takes effect when its cache expires.

**Several instances** need Postgres. The replay cache, device and CIBA polling throttling, server-side sessions and their outbox, and the signing keys are all in the database. Every background job is safe to run on every instance.

## Keys and data protection

- **Static keys:** `[[signing_keys]]` are PKCS#8 PEM files, with an optional certificate chain. SAML needs a certificate, or a managed RSA key. `[[validation_keys]]` are published in the JWKS and never used to sign: a retired key, or one a migration brought.
- **Automatic key management:** `[protocol.key_management]`, on by default.
  - It creates, rotates (`rotation_interval`, 90 days), announces ahead of use (`propagation_time`, 14 days) and retires (`retention_duration`, 14 days) keys of each `signing_algorithms` entry.
  - Keys live in `key_path` with the memory store, or in Postgres, protected with the data protection key ring (`data_protect_keys`).
  - Rotation happens when keys are read, not on a timer. With static keys configured, the first static key signs.
- **The data protection key ring:** `[[data_protection.keys]]`, each an `id` and 32 random bytes in base64.
  - It protects stored signing keys, and seals what the server hands to browsers and the UI: the session cookie, the error and logout messages, DPoP nonces and the interaction binding.
  - The first key protects new data; every key can unprotect. To rotate, add a new key first in the list and keep the old one until nothing it protected is still needed.
  - Without a ring, the memory store keeps a generated key for stored signing keys in `{key_path}/data-protection.key`, and messages to browsers are sealed with a per-process key, which doesn't survive a restart or reach other instances. Postgres refuses to start when stored keys must be protected and no ring is configured. Configure a ring in any real deployment.

## Background jobs

| Job | Settings | What it does |
|---|---|---|
| Storage purge | `[protocol.storage_purge]` (hourly, batches of 100) | Removes expired grants, pushed authorization requests, device codes, and replay and throttling entries. With `[store] remove_consumed_grants`, it also removes consumed grants after `consumed_grant_cleanup_delay` |
| Session cleanup | `[protocol.server_side_sessions]` (every 10 minutes) | With server-side sessions, removes expired sessions and queues their logout processing |
| Outbox | `[protocol.outbox_processor]` (every 30 s) | Sends the back-channel logouts and revokes the tokens of expired sessions, retrying failures with backoff |

Each job's first run comes after a random part of its interval (`fuzz_*`), so instances started together don't run them at the same moment.

## Observability

- **Logs** go to stdout through `tracing`: `[log] format` is `pretty` or `json`, and `level` is a `tracing` filter such as `info` or `rustid_http=debug,info`.
- **Events** are logged as JSON when their category is enabled (`[protocol.events]`).
- **OpenTelemetry:** with `[telemetry.otlp]`, traces and metrics go over OTLP/HTTP (`endpoint`, `headers`). Metrics are exported every `metrics_interval`; Counters include `tokenservice.token_issued`.

## Health and shutdown

- `GET /health` is liveness: 200 while the process serves.
- `GET /ready` is readiness: 200 when the persisted grant store answers and a signing key is available, and 503 with `{"status":"unavailable","reason":"store"|"signing_key"}` otherwise. Each check gives up after 2 s, and error details go to the log, never to the response.
  - With key management, the first key is made on demand, so the first probe after a fresh start can be 503.
- **Shutdown:** SIGTERM or SIGINT stops accepting connections, lets requests in flight finish, stops the jobs and flushes telemetry. That is what `docker stop` and Kubernetes send.

## Security notes

- **Admin API** (`[admin]`): every key is at least 32 characters. Serve it over TLS, and give each caller its own key. See [admin-api.md](admin-api.md).
- **Dynamic client registration** (`[dynamic_client_registration]`): callers need one of `initial_access_tokens` (each at least 32 characters). `open = true` lets anyone who reaches the endpoint create clients, so keep it to test environments. See [dynamic-client-registration.md](dynamic-client-registration.md).
- **Interaction API** (`[interaction] api_keys`): every key is at least 16 characters. Only the UI app's back end calls it. See [interaction-api.md](interaction-api.md).
- **Upstream federation** (`identity_providers_file`): give client secrets as `secretEnv`, so the providers file holds no secrets. Providers must be `https`; `[federation] allow_insecure_loopback` is for tests and demos. `[federation] ca_file` adds CA certificates for providers behind a private PKI. See [federation.md](federation.md).
- **Hooks:** HTTPS, or HTTP to loopback only. Each call carries a JWT the server signs, so a hook can tell the server's calls from anyone else's. See [hooks.md](hooks.md).
- **The reference UI** (`[reference_ui]`) signs people in without real credentials. It is for tests and the demo, never production.
- **A migration bundle** holds private keys in the clear. Keep it owner-only, and delete it after the import ([migration.md](migration.md)).
