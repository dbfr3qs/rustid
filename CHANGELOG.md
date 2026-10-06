# Changelog

All notable changes to rustid are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a
minor version may change configuration or APIs.

## [Unreleased]

## [0.6.1] - 2026-10-06

### Fixed

- Upstream logout: a back-channel logout that fails after its token was accepted answers 500 and leaves the token unused, so the provider's retry works; a replay cache failure is a 500, not a 400. A failed write of the upstream session record no longer fails the sign-in.
- A failed discovery is remembered for a minute, and a stored provider that can't be resolved is logged once a minute, instead of on every sign-in or sign-out.
- Admin: one unreadable stored provider no longer makes `GET /admin/identity-providers` fail; malformed provider JSON is reported without repeating the values sent; an import racing another instance is retried.
- Multi-tenant: `{tenantid}` is accepted only as a path segment of the discovery issuer, and only that segment is filled in.
- The federation cookies' path follows the issuer, so callbacks work behind a proxy that strips a path prefix the issuer has. The signout callback answers only for a configured provider. Federation pages are never cached, and an upstream `access_denied` for a request that can't be answered any more shows the error page.

### Changed

- `User Logout Success` is raised once per ended session, with its `SubjectId` and `SessionId`.
- Upstream session records are kept only for providers with `backChannelLogout`.
- On Postgres, providers from `identity_providers_file` are listed in the file's order on every start, then those made through admin, as on the memory store.
- A provider listing a tenant twice is refused.
- `upstream_error` events include the provider's `error_description`.

## [0.6.0] - 2026-10-06

### Added

- Logout started by an upstream provider. With `backChannelLogout`, the provider's back-channel logout (`POST /federation/<scheme>/backchannel-logout`) ends the rustid sessions its logout token names, by `sid` or by `sub`. It needs server-side sessions. With `frontChannelLogout`, its front-channel logout (`GET /federation/<scheme>/frontchannel-logout`) ends the browser's session. Either way rustid's clients are told through their own logout channels, and `User Logout Success` and `User Logout Failure` events are raised.
- `idTokenSignedResponseAlg` on a provider: id tokens and logout tokens must be signed with that algorithm.
- The sessions keep the upstream session id (`sid`).
- The relying-party conformance run covers the suite's back-channel, front-channel and RP-initiated logout plans.

## [0.5.0] - 2026-10-06

### Added

- Identity providers through the admin API (`/admin/identity-providers`), on the memory and Postgres stores. Inline secrets and private keys are stored encrypted with the data protection key ring and never read back. A provider created, changed, disabled or deleted through admin takes effect at the next sign-in.
- Providers can carry their `private_key_jwt` key and certificate inline (`key`, `certificate`).

### Changed

- `identity_providers_file` is imported into the configuration store at start, like the other configuration files: on Postgres, re-imported on every start, overwriting the providers it defines. A provider removed from the file is no longer removed on Postgres: delete or disable it through the admin API as well.

## [0.4.0] - 2026-10-05

### Added

- Multi-tenant providers: with `multiTenant: { "tenants": [...] }`, one provider entry uses Entra ID's shared `organizations` or `common` endpoint and accepts the listed tenants. Each token's `tid` must be listed, and its `iss` must be that tenant's issuer. A token from any other tenant fails as `tenant_not_allowed`.

## [0.3.0] - 2026-10-05

### Added

- Upstream sign-out: with `"signOut": true`, signing out of rustid also signs the user out of the upstream provider (OpenID Connect RP-Initiated Logout 1.0), and comes back through `/federation/<scheme>/signout-callback`. The provider's id token is kept as `id_token_hint` when server-side sessions are on.

### Changed

- The logout continuation can redirect to an upstream provider before the return URL. The reference UI follows that redirect and shows its signed-out page at `/account/logout/done` afterwards.

## [0.2.0] - 2026-10-05

### Added

- Upstream federation: users sign in through other OpenID Connect providers configured in `identity_providers_file` (docs/federation.md). rustid runs the authorization code flow with PKCE, validates the id token as OpenID Connect Core §3.1.3.7 requires, and derives the local subject from the provider's issuer and subject. Sign-in starts from a login page button (`identityProviders` in the login context), from `acr_values=idp:<scheme>`, or straight away for a client with one provider and no local login. Client authentication to providers is `client_secret_basic`, `client_secret_post` or `private_key_jwt`, and a provider can also be asked for userinfo.
- `User Login Success` and `User Login Failure` events for upstream sign-ins.
- The demo signs in through a second rustid as an upstream provider.
- The OpenID Foundation relying-party test plan runs against the federation (`scripts/conformance.sh rp`).

### Changed

- With `reference_ui.users_profile_service`, subjects that aren't in the users file are answered from their session's claims and count as active, so users signed in another way stay signed in.

## [0.1.2] - 2026-10-05

### Changed

- Documentation comments describe rustid in its own terms, and a CI check (`scripts/check-doc-references.sh`) keeps comments citing rustid's own items.

## [0.1.1] - 2026-10-05

### Changed

- The migration bundle format is now named `rustid-migration-bundle`. `rustid-server import` still reads bundles with the earlier name, `rustid-ef-export`.

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

[Unreleased]: https://github.com/dbfr3qs/rustid/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/dbfr3qs/rustid/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/dbfr3qs/rustid/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/dbfr3qs/rustid/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/dbfr3qs/rustid/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/dbfr3qs/rustid/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/dbfr3qs/rustid/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/dbfr3qs/rustid/releases/tag/v0.1.0
