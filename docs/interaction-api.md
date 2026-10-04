# The interaction API

rustid has no login, consent or logout pages of its own. A UI app you run renders them, and talks to the server through the interaction API: an HTTP API for everything a login, consent or logout page needs from the server. The source is `crates/rustid-http/src/interaction_api.rs`. The reference UI (`crates/rustid-server/src/reference_ui.rs`) is a complete client of it, and the model to copy.

## Authentication and the two halves

- **The API** (`/interaction/*`) is called by the UI app's back end, with `Authorization: Bearer <key>`. Keys come from `[interaction] api_keys`, each at least 16 characters, and with no keys the API is off. A missing or wrong key answers 401.
- **Calls about the user** (consent, logout, device, CIBA, session) forward the browser's cookies (`Cookie` header). The server then knows which session the call is about. Forward the browser's `Host` too, so the URLs it returns are the browser's.
- **Continuations** (`/connect/interaction/*`): calls that must change the browser's cookies (sign in, sign out, IdP-initiated SAML SSO) answer a `continueUrl`. Send the browser there. A continuation is:
  - one-time: a second visit answers 400 `invalid_continuation`;
  - valid for 5 minutes (`CONTINUATION_LIFETIME_SECONDS`);
  - bound to the browser. A login continuation only works in the browser the authorize request redirected, which carries the `idsrv.interaction` binding cookie. Logout and SAML continuations only work in the session that asked.

  Continuations need no API key: the token and the binding are the credential.

Errors are JSON, `{"error": "<code>"}`, with 400 for a bad request and 404 when there is nothing to show. Bodies are JSON (`Content-Type: application/json`, or 415) with camelCase names, and unknown fields are refused (400 `invalid_body`).

## Login

1. The authorize endpoint sends the browser to `protocol.user_interaction.login_url` with `ReturnUrl=…` (the parameter name is `login_return_url_parameter`).
2. `GET /interaction/login?returnUrl=…`: the authorization context, or 404 when the return URL isn't a valid pending request. Use it to show who is asking.
3. The UI authenticates the user however it likes.
4. `POST /interaction/login`:

   ```json
   { "returnUrl": "/connect/authorize/callback?...", "subjectId": "alice",
     "idp": "local", "amr": ["pwd"], "authTime": 1791000000,
     "claims": [{ "type": "name", "value": "Alice" }], "remember": false, "allowRefresh": null }
   ```

   It answers `{"continueUrl": ".../connect/interaction/continue?token=…"}`. `returnUrl` must have the shape of an authorize callback or a SAML SSO callback (otherwise 400 `invalid_return_url`). That it is a pending request of this browser is checked at the continuation, by the binding cookie. A missing `subjectId` is 400 `invalid_body`, and an empty one 400 `invalid_subject`. `remember` makes the session cookie persistent.
5. The browser visits `continueUrl`. The server writes the session cookies and redirects it to `returnUrl`, which finishes the protocol flow.

### Walk-through: the reference UI's interactive login

The reference UI (`[reference_ui] interactive = true`) signs a user in like this:
1. The authorize endpoint redirects the browser to `/Account/Login?ReturnUrl=…`.
2. The page calls `GET /interaction/login?returnUrl=…` with its own API key and the browser's cookies, and shows the form with the context's `clientName` (or `clientId`), `scopes` and `loginHint`. The return URL goes in a hidden field. A 404 (or 400) means the return URL isn't a pending request: the page answers 400 with "There is no sign-in request to complete".
3. `POST /account/login` checks the username and password against `users_file`. `button=cancel` denies the request instead, with `POST /interaction/deny` and the return URL.
4. It calls `POST /interaction/login` with the return URL, the user's `subjectId` and claims, and `remember` (the "Remember me" box), then answers `302` to the returned `continueUrl`.
5. The browser visits the continuation, which sets the session cookie, then goes on to the authorize callback. The callback either answers the client or, when consent is needed, redirects to the consent page (next section). The reference UI's consent page reads `GET /interaction/consent?returnUrl=…` and posts the user's choice to `POST /interaction/consent`.

The reference UI also refuses cross-site form posts: it checks `Sec-Fetch-Site`, or else `Origin` against its own. Copy that check, because the session cookie is `SameSite=None`.

## Consent

- `GET /interaction/consent?returnUrl=…`: what a consent page shows (the client and the requested scopes and resources).
- `POST /interaction/consent`:

  ```json
  { "returnUrl": "...", "scopes": ["openid", "api1"], "rememberConsent": true, "description": "laptop" }
  ```

  `POST /interaction/deny` takes `{"returnUrl": "...", "error": "access_denied", "errorDescription": "..."}`. Both answer `{"redirectUrl": "..."}`: send the browser there.

## Errors

`GET /interaction/error?errorId=…`: the error the server sent to `error_url` (get error context), or 404.

## Logout

1. The end session endpoint sends the browser to `logout_url` with `logoutId=…`.
2. `GET /interaction/logout?logoutId=…` (with the browser's cookies): the logout context (get logout context). It includes the client, the post-logout redirect URI, whether to show a prompt, and the front-channel logout iframe URL.
3. `POST /interaction/logout` with `{"returnUrl": "/local/path"}` (a local URL) answers `{"continueUrl": ".../connect/interaction/logout?token=…"}`.
4. The browser visits it. The server signs the session out (back-channel notifications sent, coordinated clients' tokens removed, both session cookies deleted) and redirects to `returnUrl`.

## The current session

`GET /interaction/session` (with the browser's cookies): the signed-in user (`subjectId`, `sessionId`, `idp`, `amr`, `authTime`, `claims`) or 404.

## Server-side sessions

With `[server_side_sessions]` enabled (otherwise 404 `server_side_sessions_disabled`):

- `GET /interaction/sessions?subjectId=&sessionId=&displayName=&count=&resultsToken=&prior=`: a page of sessions (query sessions).
- `POST /interaction/sessions/remove` (remove sessions):

  ```json
  { "subjectId": "alice", "sessionId": null, "clientIds": null,
    "revokeTokens": true, "revokeConsents": true, "removeServerSideSession": true,
    "sendBackchannelLogoutNotification": true }
  ```

  It needs `subjectId` or `sessionId` (otherwise 400 `invalid_filter`), and answers 204.

## Device flow

- `GET /interaction/device?userCode=…`: the pending device authorization (client and scopes), or 404.
- `POST /interaction/device` (with the browser's cookies, signed in): `{"userCode": "...", "scopes": [...], "description": "..."}` approves. `{"userCode": "...", "error": "access_denied"}` denies.

## CIBA

- `GET /interaction/ciba?id=…`: the backchannel authentication request whose `internal_id` the notification hook sent ([hooks.md](hooks.md)). Without `id`, and with the browser's cookies: the signed-in user's pending requests.
- `POST /interaction/ciba` (with the browser's cookies, signed in): `{"id": "...", "scopes": [...]}` completes it (complete login request), or `{"id": "...", "error": "access_denied"}`. A refusal answers 400 `invalid_ciba_request` with `errorDescription`.

## IdP-initiated SAML SSO

With SAML enabled:

1. `POST /interaction/saml/idp-initiated` (with the browser's cookies): `{"spEntityId": "https://sp.example", "relayState": "/dashboard"}`.
2. The server checks the service provider. A refusal is a 400 with a message, such as `"Service provider does not allow IdP-initiated SSO"` or `"User is not authenticated"`. Success answers `{"continueUrl": ".../connect/interaction/saml/idp-initiated?token=…"}`.
3. The browser visits it and gets the auto-post page that sends the signed, unsolicited SAML response to the service provider's default assertion consumer service.
