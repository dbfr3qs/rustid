# Importing a migration bundle

`rustid-server import` loads a migration bundle into the configured store: configuration, signing keys and long-lived grants exported from an existing OpenID Connect server's database. The exporter that writes bundles isn't part of this repository; this page describes what rustid reads.

## The bundle

One JSON file:

| Member | Holds |
|---|---|
| `format`, `version` | `"rustid-migration-bundle"` and `1` (the earlier name, `"rustid-ef-export"`, is still read) |
| `exported_at` | when the export ran |
| `clients` | clients in the `fixtures/clients.json` format; secrets stay hashed, as stored |
| `resources` | identity resources, API scopes and API resources in the `fixtures/resources.json` format |
| `saml_service_providers` | SAML service providers in the `fixtures/saml-service-providers.json` format |
| `signing_keys` | `id`, `algorithm`, `created`, the private key as PKCS#8 (`pkcs8`, base64) and, for X.509 keys, the certificate (`certificate`, DER, base64) |
| `grants` | persisted grants: `key`, `type`, `subject_id`, `session_id`, `client_id`, `description`, `creation_time`, `expiration`, `consumed_time`, and `data`, the grant itself |
| `skipped` | what the export left out, by kind (reported, not imported) |

The bundle holds private keys in the clear: keep it owner-only, and delete it once the import is done.

## What moves

| Data | Moves | Notes |
|---|---|---|
| Clients, identity resources, API scopes, API resources | yes | Secrets stay hashed |
| SAML service providers | yes | |
| Signing keys | yes | Re-protected under rustid's `[[data_protection.keys]]`. Tokens signed before the move keep verifying, and new ones are signed with the same keys until rotation |
| Refresh tokens | yes | They redeem at rustid with the same handles |
| Reference tokens | yes | Introspection keeps answering for them |
| User consents | yes | |
| Authorization codes, device codes, CIBA requests, pushed authorization requests | no | Short-lived; finish or restart flows in progress |
| Server-side sessions | no | Users sign in again |
| Expired grants | no | |

Signing keys configured outside the database aren't in a bundle. Configure the same key as a `[[signing_keys]]` entry.

## Importing

With the Postgres store, everything is imported:

```
rustid-server --config rustid.toml import bundle.json
```

The import prints what it imported, what the export left out, and any warnings. For example, a migrated key whose algorithm `protocol.key_management.signing_algorithms` doesn't list isn't published until it is added. Configure `[[data_protection.keys]]` first: the keys are protected under it.

Running the import again updates and never duplicates, and it never deletes: an entity removed at the source between two exports stays at rustid. In detail:
- configuration is upserted, as `clients_file` is at startup;
- existing keys are left alone;
- grants are upserted by key.

The memory store keeps grants in process memory, so there it writes files the server loads instead, and the import reports the grants it didn't carry over. `--out-dir` is refused with the Postgres store.

```
rustid-server --config rustid.toml import bundle.json --out-dir migrated/
```

The output directory holds:
- `clients.json`, `resources.json` and `saml-service-providers.json`, for `clients_file`, `resources_file` and `[saml] service_providers_file`;
- `keys/`, for `protocol.key_management.key_path`.

## Checking

- Redeem a refresh token issued before the move at `/connect/token`.
- Check that `/.well-known/openid-configuration/jwks` lists the migrated key ids.
