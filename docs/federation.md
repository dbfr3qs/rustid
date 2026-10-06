# Upstream federation

rustid can sign users in through other OpenID Connect providers: your organisation's Entra ID, Okta, Keycloak or Google Workspace, or another rustid. rustid is then a relying party of that provider. It runs the authorization code flow with PKCE, validates the id token as OpenID Connect Core requires, and signs the user in to rustid. The clients of rustid see an ordinary rustid session, with `idp` naming the provider.

Upstream providers must be standards-compliant OpenID Connect providers. OAuth 2.0-only providers that aren't OpenID Connect (GitHub, Facebook) aren't supported.

## Configuring providers

Providers come from `identity_providers_file`, the admin API (`/admin/identity-providers`, [admin-api.md](admin-api.md#identity-providers)), or both. The file is imported into the store at start, and admin changes take effect at the next sign-in. On Postgres, a provider the file defines is overwritten from the file at every start, so manage each provider in one place.

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
| `authority` | The provider's issuer. rustid reads `<authority>/.well-known/openid-configuration`, and the document's `issuer` must equal `authority` exactly (with `multiTenant`, the authority with one path segment replaced by `{tenantid}`). It must be `https` |
| `clientId` | rustid's client id at the provider |
| `clientAuthentication` | How rustid authenticates to the provider's token endpoint. See below |
| `scopes` | `["openid", "profile", "email"]` by default. Must contain `openid` |
| `claims` | The id token claims copied into the session. By default these are the OpenID Connect standard claims (`name`, `email`, `email_verified`, `preferred_username` and the others) |
| `userinfo` | `false` by default. When `true`, rustid also calls the provider's userinfo endpoint with the access token, and its claims join the id token's |
| `multiTenant` | `{"tenants": ["<tenant id>", …]}`: one entry for a shared multi-tenant endpoint, accepting the tenants listed (see Entra ID with many tenants) |
| `signOut` | `false` by default. When `true`, signing out of rustid also signs the user out of the provider (see Signing out) |
| `backChannelLogout` | `false` by default. When `true`, the provider's back-channel logout ends rustid sessions (see Logout started by the provider) |
| `frontChannelLogout` | `false` by default. When `true`, the provider's front-channel logout ends the browser's rustid session (see Logout started by the provider) |
| `idTokenSignedResponseAlg` | The id token signing algorithm registered at the provider, such as `RS256`. When set, id tokens and logout tokens signed with any other algorithm are refused. By default rustid accepts any asymmetric algorithm the provider's discovery document lists in `id_token_signing_alg_values_supported` |

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
- **Entra ID (many tenants):** see below.
- **Okta:** set `authority` to `https://<your-domain>.okta.com/oauth2/default` for the default authorization server, or to your custom authorization server's issuer.
- **Keycloak:** set `authority` to `https://<host>/realms/<realm>`.
- **Google Workspace:** set `authority` to `https://accounts.google.com`. This endpoint signs in *any* Google account, not only your organisation's (see Who can sign in, below). Add `hd`, the hosted domain, to `claims` and refuse other domains.

### Entra ID with many tenants

One provider entry can use Entra ID's shared `organizations` (or `common`) endpoint, and accept users from a list of tenants:

```json
{
  "scheme": "entra",
  "displayName": "Work account",
  "authority": "https://login.microsoftonline.com/organizations/v2.0",
  "clientId": "<multi-tenant application id>",
  "clientAuthentication": { "secretEnv": "ENTRA_SECRET" },
  "multiTenant": {
    "tenants": ["<tenant id>", "<tenant id>"]
  }
}
```

The shared endpoint's discovery document names its issuer as `https://login.microsoftonline.com/{tenantid}/v2.0`. With `multiTenant`, rustid accepts that issuer: the authority with one path segment replaced by `{tenantid}`. For each sign-in:
1. the id token's `tid` must be one of `tenants`, otherwise the sign-in fails as `tenant_not_allowed`;
2. the token's `iss` must be the template with that tenant id, so `https://login.microsoftonline.com/<tid>/v2.0`.

The list is required, and there is no wildcard: "any tenant" would let anyone with an Entra ID tenant of their own sign in. Tenant ids are compared without case.

The subject is derived from the per-tenant issuer, so the same user id in two tenants gives two subjects.

The tenant that counts is the one that issued the token: for the `organizations` endpoint, the user's home tenant. A guest invited into a listed tenant from an unlisted one is refused, unless their home tenant is listed too.

When the provider sends `iss` in the authorization response (RFC 9207), it must be a listed tenant's issuer, and the id token's issuer must match it.

## Who can sign in

rustid accepts every user the provider authenticates. A single-tenant provider (an Entra ID tenant, your Okta or Keycloak realm) only authenticates your organisation's users. A public or multi-tenant endpoint, such as Google's, authenticates anyone with an account there.

To restrict users to an organisation behind a multi-tenant endpoint, use `multiTenant` with the tenants you accept (Entra ID), or copy the claim that names the organisation into the session (`claims`, for example Google's `hd`) and refuse other values in a `subject_active` hook ([hooks.md](hooks.md)). Also limit each client to the providers it should use with `identityProviderRestrictions`.

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
| `tenant_not_allowed` | A multi-tenant provider's token came from a tenant that isn't listed, or has no `tid` |
| `stale_authentication` | `max_age` was sent, and the provider's `auth_time` is missing or older |

A successful sign-in raises `User Login Success` (id 1000), with `Provider`, `ProviderUserId` and `SubjectId`.

## Signing out

With `signOut`, signing out of rustid also signs the user out of the provider, following OpenID Connect RP-Initiated Logout 1.0.

1. rustid signs the session out as usual: its cookies go, and back-channel notifications go to its clients.
2. If the provider advertises an `end_session_endpoint`, rustid sends the browser there with:
   - `client_id`;
   - `post_logout_redirect_uri` set to `<rustid issuer>/federation/<scheme>/signout-callback`;
   - a `state` bound to the browser by a sealed cookie;
   - `id_token_hint`, but only with server-side sessions: only they keep the provider's id token, which would make a session cookie too large.
3. The provider returns the browser to the signout callback, which checks `state` and continues to the return URL the login UI gave the logout call (kept server side, so the cookie stays small). The login UI's signed-out page, with its front-channel iframes, is shown then. Its UI must have worked out the iframe URL before signing out ([interaction-api.md](interaction-api.md#logout)).

Register the signout callback with the provider as a post-logout redirect URI.

If the provider can't be reached, or never sends the browser back, the user is still signed out of rustid. A signout callback with a missing or wrong `state` shows a signed-out page and never redirects.

The logout continuation (`/connect/interaction/logout?token=…`) may now redirect to the provider instead of to the return URL. The interaction API has always had the browser follow that redirect. A UI that visits the continuation itself must send the browser to its `Location` when it isn't the return URL, as the reference UI does.

## Logout started by the provider

When the user signs out at the provider, or the provider ends their session, it can tell rustid. rustid then ends the rustid sessions that came from it. As for any rustid sign-out, it revokes the tokens tied to the session and tells rustid's clients through their back-channel and front-channel logout.

### Back channel

OpenID Connect Back-Channel Logout 1.0, supported by Okta, Keycloak and rustid among others. Set `backChannelLogout`, and register this URI with the provider as the client's `backchannel_logout_uri`:

```
<rustid issuer>/federation/<scheme>/backchannel-logout
```

Back-channel logout needs server-side sessions (`[server_side_sessions]`). Without them there is nothing on the server to end, and the endpoint answers 501.

The provider posts a `logout_token`. rustid checks it as the specification requires:
- the signature, with the provider's keys and an algorithm it accepts for id tokens;
- `iss`, as for id tokens;
- `aud` contains `clientId`;
- `iat` is present and not in the future, and `exp`, if present, has not passed;
- `jti` is present and not seen before (rustid remembers it for 5 minutes);
- `events` has the back-channel logout event;
- `sub` or `sid` is present, and there is no `nonce`.

A token with `sid` ends the rustid session that started from that provider session. A token with only `sub` ends every rustid session of that user. rustid answers 200, also when no session matched, or 400 with `{"error":"invalid_request"}` for a token that fails a check.

### Front channel

OpenID Connect Front-Channel Logout 1.0, as Entra ID uses it. Set `frontChannelLogout`, and register this URI with the provider as the front-channel logout URL, with `frontchannel_logout_session_required` true where the provider asks:

```
<rustid issuer>/federation/<scheme>/frontchannel-logout
```

The provider loads that page in a hidden iframe, with `iss` and `sid` in the query. rustid ends the browser's session if it came from that provider and, when they are given, `sid` is the provider session it started from and `iss` is the provider's issuer. Otherwise nothing happens. The page always answers 200, and it may be framed by any site.

Front-channel logout depends on the browser sending rustid's cookies inside the provider's iframe. Browsers that block third-party cookies don't, and nothing is signed out. Prefer the back channel where the provider offers it.

### Events

A logout from the provider that ends a session raises `User Logout Success` (id 1002), with `Provider`, `Channel` (`back` or `front`), and the provider's `Sub` and `Sid` where it named them. A back-channel logout token that fails a check raises `User Logout Failure` (id 1003), with `Provider`, `Channel`, `Reason` (`logout_token_invalid` or `metadata_unavailable`) and `Detail`.

## Limitations

These are not supported yet:
- SAML upstream providers;

Upstream providers must answer in the query response mode.
