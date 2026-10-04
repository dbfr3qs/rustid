# Changelog

All notable changes to rustid are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a
minor version may change configuration or APIs.

## [Unreleased]

## [0.1.0] - 2026-10-05

The first release.

### Added

- OpenID Connect and OAuth 2.0: the authorization code flow with PKCE, implicit and hybrid flows, client credentials, refresh tokens, the device flow, CIBA (poll), the password and extension grants (through hooks), introspection and revocation, userinfo, discovery and JWKS.
- Sessions and logout: server-side sessions, RP-initiated, front-channel and back-channel logout, and session management.
- Advanced security: PAR, JAR (by value and by reference), JARM, DPoP, mTLS client authentication and certificate-bound tokens, resource indicators, and FAPI 2.0.
- A SAML 2.0 identity provider: SP- and IdP-initiated SSO, single logout and signed metadata.
- An HTTP interaction API for your own login, consent and logout pages, and hooks for profile claims, custom grants and CIBA.
- An admin API for clients, resources, SAML service providers and data extension schemas, and dynamic client registration (RFC 7591, with optional RFC 7592 management).
- Memory and Postgres stores, automatic signing-key management, data protection, OpenTelemetry traces and metrics, health and readiness probes, and import from a migration bundle.
- Static Linux binaries (x86_64 and aarch64, musl) and a multi-arch container image on `ghcr.io/dbfr3qs/rustid`.
- The OpenID Foundation conformance plans in scope pass, FAPI 2.0 (with Message Signing and JARM) and FAPI-CIBA included.

[Unreleased]: https://github.com/dbfr3qs/rustid/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/dbfr3qs/rustid/releases/tag/v0.1.0
