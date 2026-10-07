# Pairwise subjects

By default every client sees the same `sub` for a user: rustid's own subject id. A client can instead see a pairwise subject (OpenID Connect Core 1.0 §8). It is derived from the client's sector, so clients in different sectors can't match a user by comparing `sub`.

## Configuration

```toml
[pairwise]
# At least 16 characters, secret, and the same on every instance.
salt = "…"
```

Prefer the environment variable `RUSTID_PAIRWISE__SALT`. With a salt set, discovery lists `subject_types_supported: ["public", "pairwise"]`; without one it lists `["public"]`, and a pairwise client is refused: the server won't start with one in `clients_file`, and admin and dynamic registration refuse to create one.

Changing the salt changes every pairwise subject, and clients then see their users as new users.

An instance without the salt never hands a pairwise client the user's own subject instead: its id tokens and userinfo answers fail with a server error, and no logout token is sent to it.

## Clients

```json
{
  "clientId": "partner-app",
  "subjectType": "pairwise",
  "sectorIdentifierUri": "https://partner.example/redirect-uris.json",
  "redirectUris": ["https://app.partner.example/callback", "https://partner.example/callback"]
}
```

| Member | Meaning |
|---|---|
| `subjectType` | `public` (the default) or `pairwise` |
| `sectorIdentifierUri` | An `https` URL whose host is the client's sector. Required for a pairwise client whose redirect URIs name more than one host. rustid doesn't fetch it for clients from `clients_file` or the admin API; dynamic registration does (see [dynamic-client-registration.md](dynamic-client-registration.md)) |
| `pairWiseSubjectSalt` | Optional; joins the server's salt for this client's subjects. Changing it changes the subjects this client sees |

The sector is the host of `sectorIdentifierUri`, or else the host the client's redirect URIs share. A client without redirect URIs (device flow, CIBA, password grant only) is a sector of its own, named by its client id. Clients in the same sector see the same pairwise subject for a user. Changing a client's sector changes the subjects it sees: moving its redirect URIs to another host, setting a `sectorIdentifierUri` on another host, or giving redirect URIs to a client that had none.

The subject is `base64url(SHA-256(sector ‖ 0x00 ‖ subject ‖ 0x00 ‖ salt))`, with `‖ 0x00 ‖ pairWiseSubjectSalt` added when the client has one.

## Where pairwise subjects appear

For a pairwise client:
- its id tokens;
- the `sub` in userinfo responses to its access tokens;
- the back-channel logout tokens rustid sends it.

Its access tokens keep the user's own subject, and so does introspection: rustid reads the user back from an access token's `sub`. A client can therefore still learn the user's own subject, by decoding its JWT access tokens or by introspecting its own access and refresh tokens. Pairwise subjects keep the user's own subject out of what the client is handed in id tokens, userinfo and logout tokens, not out of what it can look up.

Everything inside rustid keeps the user's own subject: sessions, grants, consents, events, logs and hooks.

## Hints

- **End session:** an `id_token_hint` issued to a pairwise client matches the signed-in user as that client sees them.
- **CIBA:** an `id_token_hint` reaches the CIBA user hook with the client's pairwise `sub`, which can't be turned back into a user. Pairwise clients should send `login_hint` instead.
