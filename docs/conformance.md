# OpenID Foundation conformance

rustid runs every OpenID Foundation authorization-server plan that applies to its scope. That covers basic, implicit, hybrid and form_post, config, the three logout plans, session management, dynamic registration, 3rd-party-initiated login, FAPI 2.0 (ID2, final and Message Signing) and FAPI-CIBA. The runs use:
- the suite's published images;
- the interactive reference UI, which the suite's browser fills in as `alice`.

Run them with:

    scripts/conformance.sh                 # the thirteen OIDC plans
    scripts/conformance.sh oidcc-basic     # or some, by name (the list is at the top of the script)
    scripts/conformance.sh fapi2 fapi2-final fapi2-ms fapi-ciba   # the FAPI plans, run when named
    scripts/conformance.sh rp              # the relying-party plans, against upstream federation
    KEEP=1 scripts/conformance.sh logout   # leave the suite up to look at https://localhost:8443
    scripts/conformance.sh stop

It needs Docker, git, python3 and, the first time, network access (for the images and the suite checkout that supplies `run-test-plan.py`). Everything listens on 127.0.0.1:
- rustid on `https://localhost:9443`;
- the suite on `https://localhost:8443` (its server on 18080, MongoDB on 27017).

Exported results go to `target/conformance/results`. The harness needs Linux Docker (host networking) and bash 4.

## Results

Every run used the suite image `sha256:df0385890213…` (pinned by digest in `conformance/docker-compose.yml`; `SUITE_IMAGE` overrides it) and `run-test-plan.py` from suite commit `e89fb039`, with no unexpected results.

| Plan | Variant | Modules | Result |
|---|---|---|---|
| `oidcc-basic-certification-test-plan` | discovery, static client | 35 | 25 passed, 4 review, 4 warnings and 2 skips expected |
| `oidcc-rp-initiated-logout-certification-test-plan` | code, static client | 11 | 3 passed, 8 review |
| `oidcc-frontchannel-rp-initiated-logout-certification-test-plan` | code, static client | 2 | 2 passed |
| `oidcc-backchannel-rp-initiated-logout-certification-test-plan` | code, static client | 2 | 2 passed |
| `oidcc-session-management-certification-test-plan` | code, static client | 2 | 2 passed |
| `oidcc-implicit-certification-test-plan` | discovery, static client | 54 | 35 passed, 9 review, 6 warnings and 4 skips expected |
| `oidcc-hybrid-certification-test-plan` | discovery, static client | 96 | 66 passed, 12 review, 12 warnings and 6 skips expected |
| `oidcc-formpost-basic-certification-test-plan` | discovery, static client | 35 | 25 passed, 4 review, 4 warnings and 2 skips expected |
| `oidcc-formpost-implicit-certification-test-plan` | discovery, static client | 54 | 35 passed, 9 review, 6 warnings and 4 skips expected |
| `oidcc-formpost-hybrid-certification-test-plan` | discovery, static client | 96 | 66 passed, 12 review, 12 warnings and 6 skips expected |
| `oidcc-config-certification-test-plan` | (fixed by the plan) | 1 | 1 passed |
| `oidcc-dynamic-certification-test-plan` | code; discovery, dynamic registration, `private_key_jwt` (fixed by the plan) | 23 | 8 passed, 6 review, 1 warning, 3 skips and 5 failures expected |
| `oidcc-3rdparty-init-login-certification-test-plan` | code; dynamic registration, `client_secret_basic` | 2 | 2 passed |
| `fapi2-security-profile-id2-test-plan` | plain FAPI, PAR (`simple`), OpenID Connect, `private_key_jwt`, DPoP | 58 | 51 passed, 4 review, 2 warnings and 1 skip expected |
| `fapi2-security-profile-final-test-plan` | as ID2, issuer-only client assertion audiences | 52 | 45 passed, 4 review, 2 warnings and 1 skip expected |
| `fapi2-message-signing-final-test-plan` | as final, signed requests (`signed_non_repudiation`), JARM responses | 67 | 59 passed, 4 review, 2 warnings and 1 skip expected |
| `fapi-ciba-id1-test-plan` | plain FAPI, `private_key_jwt`, poll, static client, mTLS-bound tokens | 34 | 33 passed, 1 failure expected |
| `oidcc-client-basic-certification-test-plan` (rp) | static client | 14 | 13 passed, 1 skip expected |
| `oidcc-client-back-channel-logout-rp-basic` (rp) | code, static client, `client_secret_basic` | 8 | 8 passed |
| `oidcc-client-front-channel-logout-rp-basic` (rp) | code, static client, `client_secret_basic` | 1 | 1 review |
| `oidcc-client-rp-initiated-logout-rp-basic` (rp) | code, static client, `client_secret_basic` | 3 | 3 passed |

The *rp* plans test rustid as a relying party: the suite is the upstream provider, and `conformance/rp/run.py` drives each module in place of a browser. It signs in through the suite, and in the logout plans signs out at rustid, which signs out at the suite. The suite then posts a logout token to rustid's back-channel logout endpoint (a broken one in the negative modules, which rustid refuses with 400), or frames its front-channel logout endpoint. `idtoken-sig-none` is skipped because rustid never accepts unsigned id tokens.

*Review* modules completed without failures. They wait for a person to confirm the screenshot the browser took (an error page, a second login, the signed-out page), as certification requires. The runs record the screenshots.

## The instances

The OIDC plans use `conformance/rustid.toml`. The others each have an instance of their own, so every plan keeps its configuration:

- **FAPI 2** (`conformance/fapi2/rustid.toml`, `https://localhost:9444`):
  - PS256 id tokens and client assertions;
  - a 60-second JWT clock skew;
  - PS/ES DPoP proofs only;
  - a 65-second PAR lifetime;
  - `tls.cipher_suites = "fapi"`;
  - the protected resource `/fapi2/resource` (`[protected_resource]`), which the plan calls with its DPoP-bound tokens.

  Its two `private_key_jwt` clients require PAR, PKCE and DPoP, with 60-second codes; `conformance/fapi2/make-keys.py` made their keys. The committed private JWKs (and the FAPI-CIBA client certificates) are test-only keys, made for these runs. The browser scripts for the modules that need a person to drive them are in `conformance/make-plans.py`: error pages, a reused or expired `request_uri`, and cancelling at login.
- **FAPI 2.0 final** (`conformance/fapi2-final/rustid.toml`, `https://localhost:9449`): the FAPI 2 instance and clients, with `issuer_only_client_assertion_audience` (final 5.3.2.1-8). ID2 must also accept the token and PAR endpoint URLs, so the two profiles run against separate instances.
- **FAPI 2.0 Message Signing** (`conformance/fapi2-ms/rustid.toml`, `https://localhost:9446`): the FAPI 2 instance plus issuer-only client assertion audiences, JARM (`[protocol.jarm]`), `request_object_max_lifetime = "01:00:00"` and PS256/ES256 request objects. Its clients require request objects.
- **FAPI-CIBA** (`conformance/fapi-ciba/`, `https://localhost:9445`): poll mode, mTLS with certificate-bound tokens (its clients set `requireCertificateBoundTokens`), and a 60-minute `request_object_max_lifetime`. The suite approves and refuses through `automated_ciba_approval_url`, served by `conformance/fapi-ciba/approver.py` (conformance only). The approver serves rustid's CIBA user and notification hooks, signs alice in at the reference UI, and completes the pending request through the interaction API.
- **Dynamic registration** (`conformance/dynamic/rustid.toml`, `https://localhost:9447`):
  - dynamic client registration open, with RFC 7592 read and delete (`client_management`), for this run only;
  - `registration_endpoint` in discovery (`Inferred`);
  - request objects by reference, trusting the suite's CA (`[request_uri] ca_file`);
  - `default_scopes` for registrations without a scope, and `require_pkce = false`, because the OIDC plans send neither.

## Expected results

Each is listed with its reason in `conformance/expected/`:
- `oidcc-server` warns that id tokens carry `idp`, which every id token carries.
- `oidcc-ensure-request-with-acr-values-succeeds` warns that there is no `acr` claim: none is issued unless the UI sets one.
- `oidcc-codereuse-30seconds` warns that reusing a code doesn't revoke the tokens it already issued (a "should").
- `oidcc-claims-essential` warns that `name` wasn't in userinfo: the `claims` request parameter isn't supported.
- `oidcc-unsigned-request-object-…` and `oidcc-ensure-request-object-with-redirect-uri` are skipped: unsigned request objects aren't supported.
- **Implicit and hybrid** (and their form_post plans) meet the same four warnings in the blocks those flows add: the id token from the authorization endpoint, or the token endpoint's. They're scoped by response type in the expected files. `oidcc-claims-essential` also warns that an essential `name` isn't added to the id token, for the same reason. `oidcc-ensure-request-without-nonce-fails` passes: rustid refuses the request on its error page, which the browser automation expects.
- **FAPI 2:**
  - `happy-flow` warns about `idp` in the id token;
  - `attempt-reuse-authorization-code-after-one-second` warns that reusing a code doesn't revoke its tokens;
  - `test-claims-parameter-identity-claims` is skipped: the `claims` parameter isn't supported.
- **FAPI 2.0 final and Message Signing:** the same three as FAPI 2 (the Message Signing plan's modules are the final plan's, run with signed requests and JARM).
- **Dynamic registration:**
  - `userinfo-rs256` fails: `userinfo_signed_response_alg` is ignored and userinfo answers JSON;
  - `registration-jwks-uri` and `refresh-token-rp-key-rotation` fail: `jwks_uri` is accepted but never fetched, and `private_key_jwt` needs `jwks`;
  - `request-uri-signed-rs256` fails: the suite's request object has no `exp`, which request objects require;
  - `server-rotate-keys` fails: it needs the signing key rotated by hand during the test;
  - `server` warns about `idp` in the id token;
  - skipped: unsigned id tokens and unsigned request objects.

  The `registration-logo-uri`, `policy-uri` and `tos-uri` modules are review: the reference UI's login page doesn't show the client's logo or links.
- **FAPI-CIBA:** `ensure-request-object-missing-iat-fails` fails: request objects don't need `iat` (RFC 9101 doesn't require it); `request_object_max_lifetime` caps `exp` - `nbf`.

## Notes on the setup

- **Static clients.** The logout plans use static clients.
- **Users.** The reference UI's users file answers profile claims (`reference_ui.users_profile_service`), so userinfo returns the user's claims.
- **FAPI 2 redirect URIs.** The suite also sends the redirect URI with `?dummy1=lorem&dummy2=ipsum` added. rustid matches redirect URIs exactly, so the clients register that URI too.
- **FAPI 2 TLS.** rustid terminates TLS itself. `tls.cipher_suites = "fapi"` limits TLS 1.2 to the ECDHE-RSA AES-GCM suites FAPI2-SP-ID2-5.2.2 permits; with the ECDSA conformance certificate, that means TLS 1.3 only.
- **FAPI 2 scope.** The plan asks for `offline_access`, so `refresh-token` runs.
- **FAPI 2 variant name.** The pinned suite calls the plain PAR request `authorization_request_type=simple`; newer suites call it `pushed`.
- **Client management.** The suite reads registered clients back through `registration_client_uri` (3rd-party login) and deletes them after each module, through RFC 7592 (`dynamic_client_registration.client_management`).
- **Message Signing pushes.** The suite's signed pushes need two behaviours:
  - a push whose parameters are all in the request object, with no `client_id` in the form, is the authenticated client's (RFC 9126 §3);
  - a DPoP proof with a request object that names `dpop_jkt`: the two are compared after the object is merged, rather than the proof's thumbprint being treated as a duplicate parameter.
- **Back-channel TLS.** Back-channel logout tokens go to the suite over HTTPS: `back_channel_logout.ca_file` trusts the local CA whose certificate the suite's nginx serves.
