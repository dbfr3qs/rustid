# Hooks

Hooks let a service you run supply what the server can't know by itself (profile claims, whether a user is active, custom token request checks, the password and extension grants, and the CIBA user and notification steps), over HTTPS. The source is `crates/rustid-hooks/src/lib.rs`, and they are configured under `[hooks.*]` ([`examples/rustid.toml`](../examples/rustid.toml)).

## The call

Every hook is a `POST` of a JSON body with `"version": 1`, and expects a JSON answer with `"version": 1`. Other details:

- **Transport:** HTTPS, or HTTP only to a loopback address.
- **Authentication:** `Authorization: Bearer <jwt>`. The JWT is signed with the server's signing key, typed `hook+jwt`, with `iss` set to `protocol.issuer_uri` (or the literal `"rustid"` when it isn't set), `aud` the hook's URL, and a 60-second lifetime. Verify it against the server's JWKS (`/.well-known/openid-configuration/jwks`).
- **Settings, per hook:**
  - `timeout` (default 5 s);
  - `failure_policy`: `fail_closed` (the default) or `fail_open`;
  - `cache_duration` (default 0: never reuse an answer). Only the profile hooks cache.

**A failure** is a transport error, a timeout, a non-2xx status, a body that isn't JSON, a wrong `version`, or an answer that doesn't fit the contract below. What follows depends on the hook:

| Hook | On failure |
|---|---|
| `profile_claims`, `subject_active`, `token_request` | `fail_closed`: the request fails with a server error (500). `fail_open`: the default behaviour is used (the session's own claims of the requested types; the user is active; the request is accepted), and a warning is logged |
| `password_grant`, `extension_grants.*` | The request fails whatever the policy: 500 for the password grant, `invalid_grant` for an extension grant |
| `ciba_user`, `ciba_notification`, `ciba_request` | The request fails (500) whatever the policy |

**Claims** are sent and received as `{"type": "...", "value": "...", "value_type": "..."}`. Leave out `value_type` for a string.

## `profile_claims` and `subject_active`

Together they are the profile service. When neither is configured, the server uses the users file (reference UI `users_profile_service`), or the session's own claims of the requested types.

`profile_claims` is called when tokens or userinfo need a user's claims:

```json
{ "version": 1, "caller": "ClaimsProviderAccessToken", "client_id": "web",
  "subject": { "sub": "alice", "claims": [{ "type": "name", "value": "Alice", "value_type": "..." }] },
  "requested_claim_types": ["name", "email"] }
```

`caller` says what needs the claims: `ClaimsProviderAccessToken`, `ClaimsProviderIdentityToken`, `UserInfoEndpoint` or `Saml2SsoResponseGenerator`. It answers `{"version": 1, "claims": [...]}`. Only the requested claim types are kept, and absent or null `claims` means none. Answers are cached per caller, client, subject and requested types when `cache_duration` is set.

`subject_active` is called when a token or session is used, to ask whether the user is still active:

```json
{ "version": 1, "caller": "...", "client_id": "web", "subject": { "sub": "alice", "claims": [] } }
```

`caller` is one of `AuthorizeEndpoint`, `AuthorizationCodeValidation`, `AccessTokenValidation`, `UserInfoRequestValidation`, `RefreshTokenValidation`, `ResourceOwnerValidation`, `ExtensionGrantValidation`, `DeviceCodeValidation`, `BackchannelAuthenticationRequestIdValidation` or `SamlSsoEndpoint`. It answers `{"version": 1, "active": true|false}`. An inactive user's request is refused.

## `token_request`

This replaces the custom token request validator. It is called for every token request that passed validation:

```json
{ "version": 1, "grant_type": "authorization_code", "client_id": "web", "subject_id": "alice",
  "scopes": ["openid", "api1"], "parameters": { "grant_type": "authorization_code", "redirect_uri": "https://client.test/callback" } }
```

The parameters never include `client_secret`, `client_assertion`, `code`, `code_verifier`, `refresh_token` or `password` (`WITHHELD_PARAMETERS` in `crates/rustid-core/src/token_request.rs`). It answers:
- `{"version": 1}` to accept;
- `{"version": 1, "error": "<OAuth error code>", "error_description": "..."}` to refuse with that error;
- either way, an optional `"custom_response": {...}`, whose fields are added to the token response or error.

An `error` that isn't a valid OAuth error code is a failure.

## `password_grant` and `extension_grants.<grant type>`

They replace the resource owner password validator and the extension grant validator. Configuring `password_grant` enables the `password` grant. Each `[hooks.extension_grants.<type>]` enables that extension grant type, and discovery lists them.

The password grant sends:

```json
{ "version": 1, "client_id": "demo.cli", "username": "alice", "password": "...", "parameters": { "scope": "openid" } }
```

An extension grant sends `{"version": 1, "grant_type": "...", "client_id": "...", "parameters": {...}}`. The parameters leave out the same withheld names as for `token_request`. The password grant's password arrives only in its own field.

Both accept the same answers:
- `"subject": {"sub": "...", "amr": "pwd", "idp": "...", "claims": [...]}`: success for that user. `sub` and `amr` are required;
- `"error": "invalid_grant", "error_description": "..."`: refused;
- neither (extension grants only): a token for the client alone.

Optional fields in either case:
- `"custom_response": {...}`;
- `"client_id"`: issue the token to this client instead (impersonation);
- `"access_token_lifetime"`: seconds;
- `"access_token_type"`: `"jwt"` or `"reference"`;
- `"client_claims": [...]`.

## `ciba_user`, `ciba_notification` and `ciba_request`

They replace the CIBA services. Without them, no user is known (`unknown_user_id`) and notifications are only logged.

- **`ciba_user`** is called with the backchannel authentication request:

  ```json
  { "version": 1, "client_id": "...", "login_hint": "alice", "login_hint_token": null,
    "id_token_hint": null, "id_token_hint_claims": null, "user_code": null, "binding_message": "..." }
  ```

  It answers `{"version": 1, "subject": {"sub": "...", "claims": [...]}}` or `{"version": 1, "error": "...", "error_description": "..."}`. No subject, or a subject without `sub`, means `unknown_user_id`.
- **`ciba_notification`** is called with the pending login request: `internal_id`, `subject_id`, `client_id`, `scopes`, `resource_indicators`, `binding_message`, `acr_values`, `tenant`, `idp` and `properties`. Tell the user. The UI completes the request through the interaction API (`POST /interaction/ciba`, see [interaction-api.md](interaction-api.md)) with that `internal_id`.
- **`ciba_request`** is called with `client_id`, `subject_id`, `scopes`, `binding_message` and `parameters` (without client credentials or the request object). It answers `{"version": 1}` to accept or `{"version": 1, "error": "..."}` to refuse, and optionally `"properties": {...}`, which are kept with the request and sent to `ciba_notification`.

## An example receiver

The demo client hosts two hooks: the password grant at `/hooks/password` and the CIBA user hook at `/hooks/ciba/user` (`crates/rustid-demo/src/client.rs`, `crates/rustid-demo/src/password_hook.rs`). `scripts/demo.sh` wires them into the demo server's configuration (`examples/demo/rustid.toml`).
