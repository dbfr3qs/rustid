# Changelog

All notable changes to rustid are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, a
minor version may change configuration or APIs.

## [Unreleased]

### Security

- The userinfo endpoint accepted sender-constrained access tokens as plain bearer tokens: a DPoP-bound token (RFC 9449) or a token bound to a client certificate (RFC 8705) was served without its proof or certificate. It now refuses a DPoP-bound token sent as `Bearer`, and serves a certificate-bound token only over a connection presenting that certificate.

### Added

- The userinfo endpoint accepts `Authorization: DPoP` with a DPoP proof bound to the token. Refusals carry a `WWW-Authenticate` challenge for both schemes, and a `DPoP-Nonce` when the client must use one.

### Changed

- The userinfo endpoint matches the `Bearer` scheme without regard to case (RFC 7235).

## [0.12.0] - 2026-10-09

### Added

- The `claims` request parameter (OpenID Connect Core 1.0 §5.5), on authorize and PAR, in the query or a request object. Its `userinfo` and `id_token` members add claim types to userinfo and the id token, limited to the identity resources the client is allowed (when the consent page is shown, the ones the user granted), and checked again on refresh and at userinfo. Access tokens record the userinfo request as `userinfo_claims`. Discovery lists `claims_parameter_supported: true`. See [docs/claims-parameter.md](docs/claims-parameter.md).

## [0.11.0] - 2026-10-09

### Added

- Clients' keys at a `jwks_uri`: a client with `jwksUri` (dynamic registration: `jwks_uri`, https) has its keys fetched from there (the first 100) and kept for five minutes on each instance. They authenticate it with `private_key_jwt` and verify its request objects (authorize, PAR and CIBA). A token signed by a key rustid hasn't seen makes it fetch again, so clients can rotate keys. Each URL is fetched at most once a minute, one fetch at a time, and a failed fetch keeps the keys fetched before.

### Changed

- Dynamic registration accepts `private_key_jwt` and `require_signed_request_object` with `jwks_uri` alone; it previously required `jwks`. A `jwks_uri` that isn't https is refused.

## [0.10.0] - 2026-10-08

### Added

- Signed userinfo (OpenID Connect Core 1.0 §5.3.2): a client with `userinfoSignedResponseAlg` (dynamic registration: `userinfo_signed_response_alg`, one of discovery's `userinfo_signing_alg_values_supported`) gets its userinfo answers as `application/jwt`, with `iss` and `aud`, signed with rustid's key for that algorithm. Other clients, and error answers, are unchanged.

### Changed

- Dynamic registration refuses `userinfo_encrypted_response_alg` (encrypted userinfo isn't offered) and unadvertised `userinfo_signed_response_alg` values, which were previously echoed and ignored.

## [0.9.1] - 2026-10-07

Fixes from 0.9.0's final review, which 0.9.0 was released without.

### Fixed

- A client with `requireCertificateBoundTokens` that sent a DPoP proof got tokens bound to the DPoP key instead of its certificate. Such a request is now `invalid_request`, so its tokens from the token endpoint are always certificate-bound. (Tokens issued at the authorize endpoint, implicit and hybrid, aren't bound.)

### Added

- At start, rustid warns about each client in `clients_file` that validation will refuse.

### Upgrading from before 0.9.0

- 0.9.0 refuses redirect URIs with a fragment. Clients registered dynamically or imported earlier may have one; such a client is refused on every request (at authorize, and `invalid_client` at the token endpoint). Remove the fragment through the admin API, or register again.

## [0.9.0] - 2026-10-07

### Added

- `issuer_only_client_assertion_audience`: the issuer is a client assertion's only accepted audience, typed or not (FAPI 2.0 final 5.3.2.1-8). `strict_client_assertion_audience_validation` still also requires the `client-authentication+jwt` type.
- Clients can require certificate-bound tokens (`requireCertificateBoundTokens`): a token request without a client certificate is `invalid_request`, and tokens are bound to the certificate presented.

### Changed

- Redirect URIs with a fragment are refused, in client validation (a static or admin client with one is treated as invalid) and at dynamic registration (`invalid_redirect_uri`), as RFC 6749 3.1.2 requires.
- Dynamic registration refuses a non-https `initiate_login_uri`.
- The CIBA endpoint answers `invalid_request` for a bad request object, instead of `invalid_request_object` (the authorize endpoint's error, which it keeps).
- With mTLS on, the mTLS token endpoint is also accepted as a client assertion's audience.
- Conformance: FAPI 2.0 final runs against its own instance; FAPI-CIBA runs with mTLS-bound tokens and the 60-minute request object cap. Recorded failures across all the plans drop from 27 to 6.

## [0.8.0] - 2026-10-07

### Changed

- Dynamic client registration errors use RFC 7591's member names: `{"error": …, "error_description": …}`, instead of `Error` and `ErrorDescription`. Clients that read the old names must change.

## [0.7.0] - 2026-10-07

### Added

- Pairwise subject identifiers (OpenID Connect Core 1.0 §8): `[pairwise] salt` turns them on, and clients ask for them with `subjectType: "pairwise"` (and `sectorIdentifierUri` when their redirect URIs span hosts). A pairwise client's id tokens, userinfo answers and back-channel logout tokens carry its pairwise subject; access tokens and introspection keep the user's own. An instance without the salt fails closed for pairwise clients ([docs/pairwise-subjects.md](docs/pairwise-subjects.md)).
- Dynamic client registration accepts `subject_type` and `sector_identifier_uri`, fetching and checking the sector identifier document.
- The conformance run's dynamic plan includes the sector identifier modules.

### Changed

- Discovery lists `pairwise` in `subject_types_supported` when a pairwise salt is set.

## [0.6.2] - 2026-10-07

### Fixed

- Reloading the end-session callback page after a SAML-initiated logout answers again instead of 500, also after its logout session expired; while the logout is under way, the SPs' logout requests aren't sent twice.
- SAML signatures with two `Signature`, `SignedInfo` or `SignatureValue` elements are refused.
- Core endpoints are matched before SAML paths, so a SAML entity id path never shadows one.
- One stored client that can't be read no longer makes every client lookup fail on the memory store; it is left out with a warning.
- Postgres purges no longer deadlock when instances run them at once.
- A device user code taken by a concurrent request is replaced instead of answering 500.
- Signing out drops the user's sign-ins that no browser has collected yet.
- An outbox processor delay too large to add to the clock no longer panics: out-of-range delays are refused at start.
- The migration import writes nothing to `--out-dir` when the bundle fails validation, and validates in a temporary directory.
- The readiness probe's https retry works whatever the case of the URL's scheme.
- SAML certificate subjects show BMPString values as text, not as a byte list.

### Changed

- Configuration: `protocol.outbox_processor` delays must be between 0 seconds and a year (`process_interval` at least 1 second), and `[protected_resource].path` must be a path.
- Other methods on the protected resource are 405 with `Allow: GET` (unless an endpoint has the same path); the read-only schema 405 has `Allow: GET`.
- Admin: `hashAlgorithm` is read without regard to case; blank schema group codes are refused; the IdP-initiated SSO call refuses unknown members; the API resource secret call names `PlaintextValue` as the others do; entity ids with a sign are refused.
- A certificate-bound token used without a certificate gets its own error description.
- Schemas: a whitespace-only attribute code is reported as `required`.
- Telemetry: unhandled SAML processing failures are counted with the kind `SamlError`, not `StoreError`.
- Failures to make a SAML signing certificate say why.
- The migration import warns when a key lacks the certificate its algorithm's `use_x509_certificate` needs.
- The load test labels its throughput ops/s.
- `docs/operations.md`: a trusted proxy's own client certificate without `forwarded_certificate_header`.

## [0.6.1] - 2026-10-06

### Fixed

- Upstream logout: a back-channel logout that fails after its token was accepted answers 500 and leaves the token unused, so the provider's retry works; a replay cache failure is a 500, and an unreachable provider a 503, not a 400. A failed write of the upstream session record no longer fails the sign-in.
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
