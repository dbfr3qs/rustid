# The claims parameter

A client can ask for individual claims with the `claims` request parameter (OpenID Connect Core 1.0 §5.5), not only whole scopes. Discovery lists `claims_parameter_supported: true`.

```json
{
  "userinfo": { "name": { "essential": true }, "email": null },
  "id_token": { "nickname": null }
}
```

## Where it's accepted

- **Authorize and PAR:** in the query or form, as JSON, or in a signed request object, as a JSON object.
- **Not accepted:** CIBA and the device flow ignore it.

A value that isn't a JSON object, or whose `userinfo` or `id_token` member isn't an object of `null` or object values, is `invalid_request` ("Invalid claims parameter"). Other members are ignored.

## What it asks for

- **`userinfo`:** these claim types join the ones the token's scopes ask for at the userinfo endpoint.
- **`id_token`:** these types join the id token's, from the token endpoint, the authorize endpoint (implicit and hybrid) and refreshes.

Each claim is a plain request:
- `essential`, `value` and `values` don't change what's issued. rustid returns what the profile service has, and never makes up a value.
- `acr` asked for this way is ignored; use `acr_values`.

## What a client may ask for

Only claim types that belong to an identity resource the client is allowed (`allowedScopes`) are kept; the rest are dropped without an error. When the consent page is shown (the client requires consent, or the request has `prompt=consent`), only the claim types of the identity resources the user granted are kept. Refreshes and userinfo check the request again against the client's current scopes. So the parameter never gives a client a claim it couldn't get by asking for a scope.

The values come from the profile service, as for scopes: the `profile_claims` hook ([hooks.md](hooks.md)) sees the extra types in `requested_claim_types`.

## How it's carried

- **The authorization code** keeps the request.
- **Access tokens** record the userinfo request as `userinfo_claims`, one value per claim type. In a JWT access token, resource servers can see which claim types were asked for, but not their values.
- **Refresh tokens** keep the request, so new access tokens and id tokens issued on refresh carry it again.
