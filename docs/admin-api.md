# The admin API

The admin API manages configuration over HTTP. It covers API scopes, identity resources, API resources, clients, SAML service providers and data extension schemas. The source is `crates/rustid-admin/src/lib.rs`, over the services in `crates/rustid-core/src/admin` and `crates/rustid-saml/src/admin.rs`.

## Turning it on

With `[admin] enabled = true` and at least one `api_keys` entry (32 characters or more), the server serves the admin API under `/admin`:

```
curl -H "Authorization: Bearer $KEY" -H 'content-type: application/json' \
  -d '{"name":"orders.read","displayName":"Read orders"}' https://localhost:5443/admin/api-scopes
curl -H "Authorization: Bearer $KEY" 'https://localhost:5443/admin/api-scopes?name=orders&pageSize=10'
curl -H "Authorization: Bearer $KEY" https://localhost:5443/admin/api-scopes/by-name/orders.read
```

Every call carries `Authorization: Bearer <key>`; a missing or wrong key is 401. Serve the API over TLS and give each caller its own key. Bodies are JSON (1 MiB at most) with camelCase names.

## Reading, writing and errors

Reads return the item with its `id` and `version` (and `ETag`). Updates are `PUT /admin/api-scopes/{id}` with `If-Match: "<version>"`; a stale version is 412, and a missing `If-Match` 428. `DELETE /admin/api-scopes/{id}` is idempotent. Errors are `{"errors": [{"code", "message", "propertyNames"}]}` with stable codes (`already_exists` 409, `not_found` 404, `required` and `invalid_value` 400). Changes take effect at once: a new scope appears in discovery straight away.

## Queries

`GET /admin/<kind>` returns a page of items:

```json
{ "items": [...], "totalCount": 42, "totalPages": 2, "hasMoreData": true, "nextToken": null, "previousToken": null }
```

- **Paging:** `page` and `pageSize` (25 by default, 1000 at most), or `skip` and `take`, or `continuationToken` and `pageSize`.
- **Sorting:** `sort` (a field the kind names) and `direction` (`asc` or `desc`).
- **Filters:** per kind, below. Text filters match substrings.

## API scopes and identity resources

`/admin/api-scopes` (`GET /admin/api-scopes/by-name/{name}`) and `/admin/identity-resources` (`GET /admin/identity-resources/by-name/{name}`) take the JSON of `resources_file`'s `apiScopes` and `identityResources`. Queries filter by `name` and `enabled`, and sort by `name` or `enabled`.

## API resources

API resources (`/admin/api-resources`, `GET /admin/api-resources/by-name/{name}`) work the same way, and queries also filter by `scope`, with their scopes (which must exist as API scopes) and secrets: `POST /admin/api-resources/{id}/secrets` with `{"plaintextValue": "...", "hashAlgorithm": "Sha256"|"Sha512"}` stores the hash and answers the secret's id; `DELETE /admin/api-resources/{id}/secrets/{secretId}` removes it. Reads never show secret values. A `PUT` ignores `apiSecrets` (secrets change only through their own routes). Secrets imported from `resources_file` without an id get one derived from their type and value; two identical ones share it, and deleting it removes both.

## Clients

Clients (`/admin/clients`, and `GET /admin/clients/by-client-id/{clientId}`) take the same JSON as `clients_file`. A create may carry `clientSecrets` as `[{"plaintextValue": "...", "hashAlgorithm": ..., "type": ..., "description": ..., "expiration": ...}]`; they are stored hashed. After that, secrets change only through `POST /admin/clients/{id}/secrets` and `DELETE /admin/clients/{id}/secrets/{secretId}`, and a `PUT` keeps them. Unknown members are refused. A client must pass the same checks the server applies at runtime (a redirect URI for the code flow, a secret for client credentials, and so on), so admin can't save one the server would then treat as invalid. Queries filter by `clientId`, `clientName`, `enabled`, `grantType` and `allowedScope`, and sort by `clientId`, `clientName` or `enabled`. A new client, a removed CORS origin or a new secret takes effect at once.

## SAML service providers

SAML service providers (`/admin/saml-service-providers`, and `GET /admin/saml-service-providers/by-entity-id/{entityId}` with the entity id URL-encoded) take the JSON of `service_providers_file`, except that certificates are `[{"id": ..., "base64Data": "<DER, base64>", "use": "Signing"|"Encryption"}]`. Reads add each certificate's `subject`, `thumbprint` and `notAfter`. A `PUT` replaces the certificate list: certificates sent back with their `id` keep it, new ones get one. The configuration checks apply (absolute ACS and SLO URLs, unique ACS indexes, valid certificates, HTTP-POST ACS endpoints, at least one scope), and extended properties go against schema `saml-service-provider`. Queries filter by `entityId`, `displayName` and `enabled`, and sort by `entityId`, `displayName` or `enabled`. A new, changed, disabled or deleted service provider takes effect at once, on either store. On Postgres, a service provider defined in `service_providers_file` is re-imported from the file on every start (see below), so disable or change it in the file, not only through admin. The admin API accepts service providers while `[saml] enabled` is false; they are served once SAML is enabled.

## Identity providers

Upstream identity providers (`/admin/identity-providers`, and `GET /admin/identity-providers/by-scheme/{scheme}`) take the JSON of `identity_providers_file` ([federation.md](federation.md)), keyed by `scheme`, which can't change after creation.

- **Secrets and keys:** `clientAuthentication.secret`, and for `private_key_jwt` an inline `key` (a PKCS#8 PEM, with an optional `certificate` PEM), are stored encrypted with the data protection key ring. Reads never show them: they show `hasSecret` and `hasKey` instead. `secretEnv`, `keyFile` and `certificateFile` are refused through the admin API: the server would read an environment variable or a file on the caller's behalf and send it to a provider the caller chose. They work in `identity_providers_file`.
- **Updates:** a `PUT` without `secret` (or `key`) keeps the stored one when the method is unchanged. A `PUT` that changes the method must send the new method's secret or key.
- **Checks:** every write passes the same checks as the file (an https authority, the scheme's form, `openid` in the scopes), and a key must parse.
- **Postgres:** secrets and keys stored through admin need `data_protection.keys` configured, since a per-process key couldn't open them after a restart. Without one, manage providers in `identity_providers_file`.
- **Queries** filter by `scheme`, `displayName` and `enabled`, and sort by `scheme`, `displayName` or `enabled`.
- **Effect:** a new, changed, disabled or deleted provider takes effect at the next sign-in, without a restart.

## Extended properties and schemas

Every kind also takes `extendedProperties`, checked against the kind's data extension schema (`client`, `api-resource`, `api-scope` or `identity-resource`); a kind with no schema accepts none. A schema lists attribute definitions with a type (`{"kind": "scalar", "dataType": "String"|"Integer"|"Decimal"|"Boolean"|"Date"|"DateTime"}`, a `list` of an `elementType`, or a `complex` type with `properties`) and whether each is required:

```
curl -H "Authorization: Bearer $KEY" -H 'content-type: application/json' https://localhost:5443/admin/schemas \
  -d '{"schemaId":"client","attributeDefinitions":[{"code":"department","attributeType":{"kind":"scalar","dataType":"String"}}]}'
```

Schemas are managed at `/admin/schemas` (`GET`, `POST`, and `GET`/`PUT`/`DELETE /admin/schemas/{schemaId}`), or registered at start from `[admin] schemas_file`, which makes those routes read-only. Errors use fixed messages, such as "Attribute 'x' is not defined in the schema.". String-typed extended properties also appear in the runtime models' `properties`. After a schema change, reads show only the values the current schema accepts, and the next update drops the rest. Admin sets `properties` only through extended properties: an admin update of an entity whose `clients_file`/`resources_file` entry carries `properties` replaces them. With `schemas_file`, the file is the registered set: on start, schemas it doesn't list are removed.

## Admin edits and the configuration files

With the Postgres store, `clients_file`, `resources_file`, `identity_providers_file` and `[saml] service_providers_file` are imported on every start and overwrite the entities they define: admin edits to those entities (an added secret, a disabled service provider or a certificate id included) don't survive a restart. Entities created through admin and absent from the files are kept. Manage an entity either in the file or through admin, not both.

With the memory store, admin writes live until the process stops; the files are read again at start.
