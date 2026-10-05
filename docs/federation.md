# Upstream federation

rustid can sign users in through other OpenID Connect providers: your organisation's Entra ID, Okta, Keycloak or Google Workspace, or another rustid. rustid is then a relying party of that provider. It runs the authorization code flow with PKCE, validates the id token as OpenID Connect Core requires, and signs the user in to rustid. The clients of rustid see an ordinary rustid session, with `idp` naming the provider.

Upstream providers must be standards-compliant OpenID Connect providers. OAuth 2.0-only providers that aren't OpenID Connect (GitHub, Facebook) aren't supported.

## Configuring providers

Providers are a JSON array in the file `identity_providers_file` names:

```toml
identity_providers_file = "identity-providers.json"

[federation]
# CA certificates (PEM) to trust besides the system's, for providers behind
# a private PKI.
# ca_file = "upstream-ca.pem"
# http://localhost and http://127.0.0.1 authorities, for tests and demos only.
# allow_insecure_loopback = false
```

```json
[
  {
    "scheme": "examplecorp",
    "displayName": "Example Corp (Entra ID)",
    "authority": "https://login.microsoftonline.com/<tenant-id>/v2.0",
    "clientId": "<application id>",
    "clientAuthentication": { "secretEnv": "EXAMPLECORP_SECRET" },
    "scopes": ["openid", "profile", "email"]
  }
]
```

| Member | Meaning |
|---|---|
| `scheme` | The provider's identifier: lowercase letters, digits, `_` and `-`, at most 64 characters, and not `local`. It appears in the provider's URLs, in `acr_values=idp:<scheme>`, in a client's `identityProviderRestrictions`, and as the session's `idp` |
| `displayName` | The name on sign-in buttons |
| `enabled` | `true` by default. A disabled provider is never offered, and its callbacks are refused |
| `authority` | The provider's issuer. rustid reads `<authority>/.well-known/openid-configuration`, and the document's `issuer` must equal `authority` exactly. It must be `https` |
| `clientId` | rustid's client id at the provider |
| `clientAuthentication` | How rustid authenticates to the provider's token endpoint. See below |
| `scopes` | `["openid", "profile", "email"]` by default. Must contain `openid` |
| `claims` | The id token claims copied into the session. By default these are the OpenID Connect standard claims (`name`, `email`, `email_verified`, `preferred_username` and the others) |
| `userinfo` | `false` by default. When `true`, rustid also calls the provider's userinfo endpoint with the access token, and its claims join the id token's |

### Client authentication

- `client_secret_basic` (the default) or `client_secret_post`. Give the secret either as `secret` or as `secretEnv`, which names an environment variable that holds it. Use `secretEnv`, so the file can be committed without the secret.

  ```json
  "clientAuthentication": { "method": "client_secret_post", "secretEnv": "OKTA_SECRET" }
  ```

- `private_key_jwt`: rustid signs a client assertion (RFC 7523) with a key of its own:
  - `keyFile` holds the PKCS#8 PEM private key, and `keyId` is its `kid`;
  - `algorithm` is `RS256` (the default), `ES256` or `ES384`;
  - `certificateFile` is optional and holds the key's certificate. When it is given, the assertion's header carries `x5t`, the certificate's SHA-1 thumbprint. Entra ID identifies uploaded certificates this way.

  Paths are relative to the providers file.

  ```json
  "clientAuthentication": {
    "method": "private_key_jwt", "keyFile": "examplecorp-key.pem", "keyId": "rustid-1",
    "certificateFile": "examplecorp-cert.pem"
  }
  ```

rustid's redirect URI at each provider is `<rustid issuer>/federation/<scheme>/callback`. Register it with the provider.

### Examples

- **Entra ID (one tenant):** set `authority` to `https://login.microsoftonline.com/<tenant-id>/v2.0`, register the redirect URI as a Web platform redirect, and use a client secret or a certificate with `private_key_jwt`.
- **Okta:** set `authority` to `https://<your-domain>.okta.com/oauth2/default` for the default authorization server, or to your custom authorization server's issuer.
- **Keycloak:** set `authority` to `https://<host>/realms/<realm>`.
- **Google Workspace:** set `authority` to `https://accounts.google.com`. This endpoint signs in *any* Google account, not only your organisation's (see Who can sign in, below). Add `hd`, the hosted domain, to `claims` and refuse other domains.

## Who can sign in

rustid accepts every user the provider authenticates. A single-tenant provider (an Entra ID tenant, your Okta or Keycloak realm) only authenticates your organisation's users. A public or multi-tenant endpoint, such as Google's, authenticates anyone with an account there.

To restrict users, copy the claim that identifies the organisation into the session (`claims`, for example `hd` or `tid`), and refuse other values in a `subject_active` hook ([hooks.md](hooks.md)). Also limit each client to the providers it should use with `identityProviderRestrictions`.

## Signing in

There are three ways a sign-in goes through a provider:

1. **A button on the login page.** `GET /interaction/login` lists the providers the client may use in `identityProviders`, each with a `challengeUrl`. Render each as a link. The reference UI shows "Sign in with …" buttons.
2. **The `idp:` hint.** An authorize request with `acr_values=idp:<scheme>` goes straight to that provider and skips the login page, if the client may use it. `idp:local` keeps the login page.
3. **A single provider.** When a client has `enableLocalLogin: false` and exactly one provider it may use, sign-in goes straight there.

A client's `identityProviderRestrictions` limits it to the providers it names. An empty list allows every provider.

The browser goes upstream through `/federation/<scheme>/challenge` and returns to `/federation/<scheme>/callback`. rustid then signs the user in and sends the browser on to finish the client's authorize request. That completion only works in the browser that started the request.

## The user

The local subject is derived from the provider's issuer and the user's subject there: `base64url(SHA-256(iss ‖ 0x00 ‖ sub))`. OpenID Connect Core §5.7 says these two together are the only stable identifier of an upstream user. An `email` claim is not: matching accounts by email lets anyone who controls an address at any provider take over the account.

So one person who signs in through two providers has two subjects. rustid doesn't link accounts.

The session's `idp` is the scheme. Its `amr` is the provider's `amr` when the id token has one, otherwise `["external"]`, and its `auth_time` is the provider's. A `max_age` or `prompt=login` on the client's request is passed on to the provider. A client's `userSsoLifetime` is passed on as `max_age` too, whichever is smaller. When `max_age` was sent, the provider's `auth_time` must be present and no older than that, or the sign-in fails as `stale_authentication`, rather than sending the browser back and forth.

Profile hooks (`profile_claims`, `subject_active`) see these subjects like any other.

## What rustid checks

- **The correlation cookie.** A sign-in is bound to the browser by a sealed `idsrv.federation` cookie. The cookie holds `state`, `nonce` and the PKCE verifier, is scoped to the provider's callback path, and is valid for 10 minutes. A callback without it, or with a different `state`, is refused. A callback works once.
- **RFC 9207.** When the provider advertises the `iss` authorization response parameter, the callback's `iss` must be the authority.
- **The id token**, as OpenID Connect Core §3.1.3.7 requires:
  - an asymmetric algorithm the provider advertises, never `none` or `HS*`;
  - a signature by a key in the provider's JWKS;
  - the issuer;
  - the audience, and the authorized party when there are several audiences;
  - the expiry and issue time, within the clock skew;
  - the nonce;
  - a subject.
- **Key rotation.** A token signed by a key rustid hasn't seen makes it fetch the provider's JWKS again, once per sign-in and at most sixty times a minute per provider. A token without `kid` whose signature fails on the cached keys does the same.
- **Caching.** Discovery documents and key sets are cached for a day, so a key the provider withdraws is trusted until the cache expires, unless a token with an unknown key refreshes it first. Nothing is fetched at startup, so a provider that is down doesn't stop rustid from starting.
- **Userinfo.** With `userinfo`, the response's `sub` must be the id token's.

An upstream `access_denied` (the user refused, or the provider did) goes back to the client as `access_denied`. Any other failure shows a short error page. The details are in the log and in a `User Login Failure` event (id 1001), with `Provider`, `Reason` and `Detail`:

| `Reason` | When |
|---|---|
| `expired` | The callback had no correlation cookie, or its cookie had expired |
| `state_mismatch` | The callback's `state` isn't the cookie's |
| `issuer_mismatch` | The callback's `iss` isn't the authority |
| `access_denied` | The provider answered `access_denied` |
| `upstream_error` | The provider answered another error, or no code |
| `metadata_unavailable` | Discovery or the key set couldn't be read, or failed the checks |
| `token_request_failed` | The token endpoint refused the code, or answered without an id token |
| `id_token_invalid` | The id token failed a check (named in `Detail`) |
| `userinfo_failed` | The userinfo call failed, or its `sub` didn't match |
| `stale_authentication` | `max_age` was sent, and the provider's `auth_time` is missing or older |

A successful sign-in raises `User Login Success` (id 1000), with `Provider`, `ProviderUserId` and `SubjectId`.

## Limitations

These are not supported yet:
- signing out of the provider when the user signs out of rustid;
- Entra ID's multi-tenant endpoints;
- managing providers through the admin API.

Upstream providers must answer in the query response mode.
