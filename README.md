# rustid

An OpenID Connect and OAuth 2.0 server, and a SAML 2.0 identity provider, written in Rust. It is one static binary, with memory or Postgres stores. Login, consent and logout pages are yours: they talk to the server through an HTTP interaction API, and hooks let your services supply profile claims, custom grants and CIBA steps.

## Features

- **OpenID Connect and OAuth 2.0:** the authorization code flow with PKCE, implicit and hybrid flows, client credentials, refresh tokens, the device flow, CIBA (poll), the password and extension grants (through hooks), introspection and revocation, userinfo, discovery and JWKS.
- **Upstream federation:** sign users in through other OpenID Connect providers (Entra ID, Okta, Keycloak, Google Workspace), with the provider's identity checked as OpenID Connect Core requires.
- **Sessions and logout:** server-side sessions, RP-initiated, front-channel and back-channel logout, and session management.
- **Advanced security:** pushed authorization requests (PAR), JWT-secured authorization requests (JAR, by value and by reference), JWT-secured authorization responses (JARM), DPoP, mTLS client authentication and certificate-bound tokens, resource indicators, and FAPI 2.0.
- **SAML 2.0 IdP:** SP- and IdP-initiated SSO, single logout, signed metadata.
- **Administration:** an admin API for clients, resources, SAML service providers, upstream identity providers and data extension schemas; dynamic client registration (RFC 7591) with optional RFC 7592 management.
- **Operations:** automatic signing-key management, data protection, OpenTelemetry traces and metrics, health and readiness probes, a static container image, and import from a migration bundle.

The OpenID Foundation conformance plans in scope pass, FAPI 2.0 (with Message Signing and JARM) and FAPI-CIBA included ([docs/conformance.md](docs/conformance.md)).

**Not supported:** SAML upstream providers and SAML assertion encryption.

## Quick start

With Docker (x86_64 or arm64):

    docker run --rm -p 8080:8080 -e RUSTID_PROTOCOL__ISSUER_URI=http://localhost:8080 ghcr.io/dbfr3qs/rustid:0.6.1
    curl http://localhost:8080/.well-known/openid-configuration

Or download the binary for your architecture (`x86_64` or `aarch64`, static, any Linux) from the [releases page](https://github.com/dbfr3qs/rustid/releases), with `SHA256SUMS`:

    sha256sum -c SHA256SUMS --ignore-missing
    tar xzf rustid-server-0.5.0-x86_64-unknown-linux-musl.tar.gz
    rustid-server-0.5.0-x86_64-unknown-linux-musl/rustid-server --version

Either way it starts on the memory store with no clients. [docs/operations.md](docs/operations.md) covers configuration, clients, stores and TLS; [examples/rustid.toml](examples/rustid.toml) lists every setting.

## Try it in a browser

    scripts/demo.sh

This builds and starts three things:

- **rustid-server** on `https://localhost:5443`, with the interactive reference UI (a sign-in form backed by `fixtures/users.json`).
- **A second rustid-server** on `https://127.0.0.1:5444`: an upstream identity provider the first signs users in through.
- **A demo client** on `http://localhost:5002`: a small web app that signs in with the authorization code flow, PKCE and a pushed authorization request (PAR), verifies the id token against the server's JWKS, calls userinfo, and shows the claims it received.

Open http://localhost:5002, click **Sign in**, and use `alice` / `alice` or `bob` / `bob`.

- **Consent:** the server asks for your consent. Untick scopes (untick *email* and the email disappears from userinfo), tick *Remember my decision* to skip the page next time, or refuse and see the client get `access_denied`. *Cancel* on the login page refuses too.
- **Certificates:** the first run writes a local CA to `target/demo/ca.pem`. Your browser warns about the server's certificate once, or you can import that file as a trusted authority.
- **Configuration:** the demo's server config is `examples/demo/rustid.toml`. The server logs each protocol event as it happens.

Then try:

- **Refresh tokens:** grant *Offline access* on the consent page and the client gets a refresh token, which **Refresh tokens** redeems for new ones.
- **Sign out:** this ends both sessions. The client sends you to the server's end session endpoint with its id token as the hint. Sign out at the server itself (https://localhost:5443/connect/endsession) and the demo client is signed out too, through the front-channel logout iframe.
- **Sessions:** sessions are kept server side. **Your sessions at the server** (https://localhost:5443/sessions) lists where you are signed in. Sign in from a second browser and end that session from the first: the second is signed out, and its refresh tokens are revoked.
- **Federation:** on the sign-in page, *Sign in with Upstream IdP* signs in through a second rustid on https://127.0.0.1:5444 as `carol` / `carol` or `dave` / `dave`; signing out then ends the upstream session too.
- **SAML:** the demo client is also a SAML service provider. Open http://localhost:5002/saml for **Sign in with SAML** (a signed AuthnRequest, the response's signatures checked against the server's metadata at https://localhost:5443/Saml2) and **Log out (SAML SLO)**. Your browser may warn that the identity provider posts to an `http://` page; continue.
- **Other grants:**
  - `cargo run -p rustid-demo -- device` runs the device flow, approved at https://localhost:5443/device;
  - `cargo run -p rustid-demo -- ciba --login-hint alice` runs CIBA, allowed at https://localhost:5443/ciba;
  - the password grant goes through a hook the demo client hosts.
- **Admin API:** the demo enables it. The banner `scripts/demo.sh` prints shows calls to try.

## Documentation

| Document | What it covers |
|---|---|
| [docs/operations.md](docs/operations.md) | Running it: the CLI, the container, TLS and proxies, stores, keys and data protection, jobs, telemetry, health |
| [examples/rustid.toml](examples/rustid.toml) | The configuration reference: every setting, with its default (checked in CI) |
| [docs/interaction-api.md](docs/interaction-api.md) | What a login, consent and logout UI calls |
| [docs/federation.md](docs/federation.md) | Signing in through upstream OpenID Connect providers |
| [docs/hooks.md](docs/hooks.md) | The hooks your services answer: profile claims, grants, CIBA |
| [docs/admin-api.md](docs/admin-api.md) | The admin API: clients, resources, SAML service providers, schemas |
| [docs/dynamic-client-registration.md](docs/dynamic-client-registration.md) | Clients registering themselves (RFC 7591), and RFC 7592 read and delete |
| [docs/migration.md](docs/migration.md) | Importing a migration bundle |
| [docs/conformance.md](docs/conformance.md) | OpenID Foundation conformance runs |
| [docs/fuzzing.md](docs/fuzzing.md) | Fuzz targets and campaigns |
| [CHANGELOG.md](CHANGELOG.md) | What changed in each release |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributing: checks, sign-off (DCO) and licensing |
| [SECURITY.md](SECURITY.md) | Reporting a vulnerability |

## Layout

- `crates/`: the Rust workspace.
  - `rustid-core`: the protocol, with no I/O;
  - `rustid-http`: the endpoints and the interaction API;
  - `rustid-server`: the binary, configuration and the reference UI;
  - `rustid-admin`: the admin API;
  - `rustid-saml`: the SAML IdP;
  - `rustid-hooks`;
  - `rustid-store-memory` and `rustid-store-postgres`;
  - `rustid-testkit`, `rustid-fuzz`, `rustid-loadtest` and `rustid-demo`.
- `fixtures/`: clients, resources, users, SAML service providers and test-only keys. `fixtures/profiles/` holds server configurations the tests use.
- `fuzz/`: the cargo-fuzz targets.
- `conformance/`: the conformance suite setup.

## Build and test

    cargo run -p rustid-server -- --config fixtures/profiles/default.json   # http://127.0.0.1:8080
    scripts/ci-local.sh                                                     # everything CI runs

`scripts/ci-local.sh` runs fmt, clippy and the Rust tests (store contracts on memory and Postgres), the release script tests, then the container check.

Other checks, outside CI:
- `scripts/conformance.sh` runs the conformance plans (needs Docker);
- `scripts/fuzz.sh` runs the fuzz campaigns (needs nightly and cargo-fuzz).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
