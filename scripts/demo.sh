#!/usr/bin/env bash
# Runs rustid over HTTPS with the interactive reference UI, a second rustid
# as an upstream identity provider, and the demo client that signs in
# there, until ctrl-c. Needs bash and curl.
#
#   scripts/demo.sh
#   open http://localhost:5002 and sign in as alice/alice or bob/bob
#
# The first run writes a local CA and a certificate for localhost to
# target/demo. Browsers warn about it once; to avoid the warning, import
# target/demo/ca.pem as a trusted authority.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -q -p rustid-server -p rustid-demo
bin="${CARGO_TARGET_DIR:-target}/debug"

"$bin/rustid-demo" certs --out target/demo > /dev/null

pids=()
cleanup() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill "$pid" 2> /dev/null || true; done
  wait 2> /dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# The upstream identity provider first: the demo server signs users in
# through it.
"$bin/rustid-server" --config examples/demo/upstream.toml &
pids+=($!)
RUSTID_FEDERATION__CA_FILE="$PWD/target/demo/ca.pem" \
  "$bin/rustid-server" --config examples/demo/rustid.toml &
pids+=($!)
"$bin/rustid-demo" client --ca-file target/demo/ca.pem --users-file fixtures/users.json \
  --saml-key fixtures/saml/sp/sp-signing.key.pem &
pids+=($!)

# Wait until both answer; stop if either has exited (a port in use, a bad
# certificate), since its error is above.
alive() {
  for pid in ${pids[@]+"${pids[@]}"}; do kill -0 "$pid" 2> /dev/null || return 1; done
}
answers() {
  curl -fsS --max-time 2 --cacert target/demo/ca.pem -o /dev/null \
    https://localhost:5443/.well-known/openid-configuration 2> /dev/null \
    && curl -fsS --max-time 2 --cacert target/demo/ca.pem -o /dev/null \
      https://127.0.0.1:5444/.well-known/openid-configuration 2> /dev/null \
    && curl -fsS --max-time 2 -o /dev/null http://localhost:5002/ 2> /dev/null
}
ready=false
for _ in $(seq 1 50); do
  if ! alive; then
    echo "demo: the server or the client stopped; see the error above (is port 5443, 5444 or 5002 in use?)" >&2
    exit 1
  fi
  if answers; then
    ready=true
    break
  fi
  sleep 0.2
done
if [ "$ready" != true ]; then
  echo "demo: https://localhost:5443, https://127.0.0.1:5444 or http://localhost:5002 isn't answering" >&2
  exit 1
fi

cat << 'EOF'

  rustid demo
  -----------
  Client:  http://localhost:5002          <- open this and click "Sign in"
  Server:  https://localhost:5443         (discovery: /.well-known/openid-configuration)
  Users:   alice / alice, bob / bob
  Federation: on the sign-in page, "Sign in with Upstream IdP" signs in
           through a second rustid (https://127.0.0.1:5444) as carol / carol
           or dave / dave; the client then shows a subject derived from the
           upstream's issuer and subject, and idp "upstream". Signing out
           signs out of the upstream too.
  Logout:  "Sign out" in the client ends both sessions; signing out at
           https://localhost:5443/connect/endsession signs the client out
           over the front channel.
  Sessions: https://localhost:5443/sessions lists and ends your sessions.
  Password grant (a hook in the demo client checks the password):
    curl --cacert target/demo/ca.pem https://localhost:5443/connect/token \
      -d grant_type=password -d client_id=demo.cli -d client_secret=secret \
      -d username=alice -d password=alice -d scope="openid api1 offline_access"
  Device flow (a TV-style sign-in; approve it at the printed URL):
    target/debug/rustid-demo device
  CIBA (a backchannel sign-in for alice): sign in as alice at the client
  first, run the command, then allow it at https://localhost:5443/ciba:
    target/debug/rustid-demo ciba --login-hint alice
  SAML: http://localhost:5002/saml is a SAML service provider: "Sign in with
           SAML", then "Log out (SAML SLO)". (Your browser may warn that the
           IdP posts the response to an http:// page; continue.)
           IdP metadata: https://localhost:5443/Saml2
  Admin API (create a scope, then see it in discovery's scopes_supported):
    curl --cacert target/demo/ca.pem -H 'Authorization: Bearer rustid-demo-admin-key-not-for-real-use' \
      -H 'content-type: application/json' https://localhost:5443/admin/api-scopes \
      -d '{"name":"orders.read","extendedProperties":{"owner":"orders-team"}}'
  Admin API (create a machine client, then get it a token with orders-secret):
    curl --cacert target/demo/ca.pem -H 'Authorization: Bearer rustid-demo-admin-key-not-for-real-use' \
      -H 'content-type: application/json' https://localhost:5443/admin/clients -d '{"clientId":"orders",
      "allowedGrantTypes":["client_credentials"],"allowedScopes":["api1"],"clientSecrets":[{"plaintextValue":"orders-secret"}]}'
    curl --cacert target/demo/ca.pem https://localhost:5443/connect/token -u orders:orders-secret -d grant_type=client_credentials
  Admin API (the demo's upstream identity provider; disable it with a PUT
  and the button leaves the sign-in page at once):
    curl --cacert target/demo/ca.pem -H 'Authorization: Bearer rustid-demo-admin-key-not-for-real-use' \
      https://localhost:5443/admin/identity-providers/by-scheme/upstream
  Admin API (the demo's SAML service provider; disable it with a PUT and
  "Sign in with SAML" is refused at once):
    curl --cacert target/demo/ca.pem -H 'Authorization: Bearer rustid-demo-admin-key-not-for-real-use' \
      https://localhost:5443/admin/saml-service-providers/by-entity-id/http%3A%2F%2Flocalhost%3A5002%2Fsaml
  Dynamic client registration (a machine client; the response has its
  client_id and client_secret for /connect/token, and a registration_client_uri
  and registration_access_token to read or DELETE it):
    curl --cacert target/demo/ca.pem -H 'Authorization: Bearer rustid-demo-registration-token-not-for-real-use' \
      -H 'content-type: application/json' https://localhost:5443/connect/dcr \
      -d '{"client_name":"reports","grant_types":["client_credentials"],"scope":"api1"}'

  The server's certificate comes from a local CA in target/demo/ca.pem.
  Accept the browser's warning once, or import that file as a trusted CA.
  Press ctrl-c to stop.

EOF
# Until ctrl-c, or until either process exits.
while alive; do sleep 1; done
echo "demo: the server or the client stopped" >&2
exit 1
