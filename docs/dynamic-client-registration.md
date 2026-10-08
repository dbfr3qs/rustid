# Dynamic client registration

rustid serves a dynamic client registration endpoint: clients register themselves with a JSON document (RFC 7591), and the server answers with their `client_id` and, when they need one, a secret. Optionally, a registered client can read its registration back or delete itself (RFC 7592).

It is off by default.

## Enabling it

```toml
[dynamic_client_registration]
enabled = true
initial_access_tokens = ["a-long-random-token-you-give-to-each-registering-party"]

# Optional: publish it in discovery as registration_endpoint.
[protocol.discovery.dynamic_client_registration]
registration_endpoint_mode = "Inferred"   # {base}/connect/dcr; or "Static" with static_registration_endpoint
```

| Setting | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Serve `POST {path}`. |
| `path` | `/connect/dcr` | Where. |
| `initial_access_tokens` | none | Bearer tokens that may register (RFC 7591 §3), each at least 32 characters. |
| `open` | `false` | Anyone may register, without a token. For test environments only: anyone who reaches the endpoint can then create clients. |
| `secret_lifetime` | never | Generated secrets expire after this (`client_secret_expires_at` in the response). |
| `default_scopes` | none | Scopes a client gets when it asks for none. |
| `require_pkce` | the client default (required) | Whether registered code clients must use PKCE. |
| `client_management` | `false` | RFC 7592 read and delete, below. |

The server refuses to start when the endpoint is enabled with no tokens and `open` is off.

## Registering

```sh
curl -H 'Authorization: Bearer <initial access token>' -H 'content-type: application/json' \
  https://idp.example.com/connect/dcr \
  -d '{"client_name":"reports","grant_types":["client_credentials"],"scope":"api1"}'
```

The request must be `application/json`; anything else is 415. A body that isn't a registration document (invalid JSON, or a member of the wrong type) is 400 with `invalid_client_metadata`, "malformed metadata document".

### What a registration may ask for


- **Grant types:** `authorization_code` and `client_credentials`. `refresh_token` is allowed with `authorization_code` and turns on offline access. Anything else is refused.
- **Redirect URIs:** required, and absolute, with `authorization_code`. Not allowed for a `client_credentials`-only client.
- **Scopes:** `scope`, space-separated. `offline_access` is dropped: ask for the `refresh_token` grant instead.
- **Client authentication:** `token_endpoint_auth_method` is `client_secret_basic` by default.
  - With `client_secret_basic` or `client_secret_post`, the server generates a secret.
  - With `private_key_jwt`, the client sends its public keys in `jwks`; `jwks_uri` isn't fetched.
  - With `none`, the client is public and gets no secret.

  Keys sent in `jwks` are also used for signed request objects (`require_signed_request_object`).
- **Other metadata:** `client_name`, `client_uri`, `logo_uri`, `initiate_login_uri`, the logout URIs and their session flags, and `default_max_age`.
- **Signed userinfo:** `userinfo_signed_response_alg`, one of discovery's `userinfo_signing_alg_values_supported`. The client's userinfo answers are then `application/jwt`: the claims plus `iss` and `aud`, signed with rustid's key for that algorithm (OpenID Connect Core 1.0 §5.3.2). Static and admin clients set it as `userinfoSignedResponseAlg`.
- **Subject type:** `subject_type` is `public` (the default) or `pairwise`, which needs the server's `[pairwise] salt` ([pairwise-subjects.md](pairwise-subjects.md)). `sector_identifier_uri` must be `https`. rustid fetches it (through `[request_uri] ca_file`), and it must be a JSON array listing every redirect URI. A pairwise client whose redirect URIs name more than one host needs one. Problems are `invalid_client_metadata`.
- **rustid's own members:**
  - token lifetimes and types: `access_token_lifetime`, `identity_token_lifetime`, `authorization_code_lifetime`, `access_token_type`;
  - refresh token settings: `absolute_refresh_token_lifetime`, `sliding_refresh_token_lifetime`, `refresh_token_expiration`, `refresh_token_usage`, `update_access_token_claims_on_refresh`;
  - consent: `require_consent`, `allow_remember_consent`, `consent_lifetime`;
  - sign-in and other client settings: `allowed_cors_origins`, `require_client_secret`, `enable_local_login`, `identity_provider_restrictions`, `coordinate_lifetime_with_user_session`, `allowed_identity_token_signing_algorithms`.

Members it doesn't know are kept and echoed back in the response. That covers `contacts`, `policy_uri`, `id_token_signed_response_alg` and others, which have no effect.

A refusal is 400 with an RFC 7591 error body:

```json
{"error":"invalid_redirect_uri","error_description":"redirect URI required for authorization_code grant type"}
```

### The response

201 with the client's metadata: `client_id`, plus these when a secret was generated:
- `client_secret`, which is shown only here and stored hashed;
- `client_secret_expires_at` (0 means never).

The client can use it at once.

## Managing a registration (RFC 7592)

With `client_management = true`, each registration response also carries:

- `registration_client_uri`: `{issuer}{path}/{client_id}`;
- `registration_access_token`: the token for that one client. The server keeps only its hash.

With the token as a bearer token:

- `GET {registration_client_uri}` returns the registration, without the secret.
- `DELETE {registration_client_uri}` deletes the client: 204.

The response is 401 `invalid_token` in these cases:
- a wrong or missing token;
- another client's token;
- a client that wasn't registered with management on.

There is no update (PUT). Initial access tokens don't grant management.

## Not supported

- fetching `jwks_uri`;
- software statements (accepted and echoed, not checked);
- encrypted userinfo (`userinfo_encrypted_response_alg`, refused);
- implicit and hybrid clients.

[conformance.md](conformance.md) lists the conformance modules these affect.
