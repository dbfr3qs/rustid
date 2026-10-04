#!/usr/bin/env bash
# Builds the rustid image and checks it: a static binary on scratch, non-root,
# ready on the memory store with key management on, healthy by its own
# HEALTHCHECK, a CA bundle for outgoing HTTPS, and a graceful docker stop.
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE=${IMAGE:-rustid:check}
NAME=rustid-container-check
PORT=${PORT:-18089}

docker build -q -t "$IMAGE" . >/dev/null
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

user=$(docker image inspect -f '{{.Config.User}}' "$IMAGE")
[ "$user" = "65532:65532" ] || { echo "image user is '$user', want 65532:65532"; exit 1; }

docker run -d --name "$NAME" -p "127.0.0.1:$PORT:8080" \
  -e RUSTID_PROTOCOL__ISSUER_URI="http://localhost:$PORT" "$IMAGE" >/dev/null

deadline=$((SECONDS + 30))
until curl -fsS "http://127.0.0.1:$PORT/ready" >/dev/null 2>&1; do
  [ $SECONDS -lt $deadline ] || { echo "never ready"; docker logs "$NAME"; exit 1; }
  sleep 0.5
done
curl -fsS "http://127.0.0.1:$PORT/.well-known/openid-configuration" >/dev/null
curl -fsS "http://127.0.0.1:$PORT/health" >/dev/null || { echo "/health did not answer 2xx"; exit 1; }

deadline=$((SECONDS + 60))
until [ "$(docker inspect -f '{{.State.Health.Status}}' "$NAME")" = healthy ]; do
  [ $SECONDS -lt $deadline ] || { echo "never healthy"; docker inspect -f '{{json .State.Health}}' "$NAME"; exit 1; }
  sleep 1
done

tmp=$(mktemp -d)
docker cp "$NAME:/rustid-server" "$tmp/rustid-server"
file "$tmp/rustid-server" | grep -Eq "static(-pie)? linked|statically linked" \
  || { echo "not a static binary: $(file "$tmp/rustid-server")"; exit 1; }
docker cp "$NAME:/etc/ssl/certs/ca-certificates.crt" "$tmp/ca.crt"
grep -q "BEGIN CERTIFICATE" "$tmp/ca.crt" || { echo "no CA bundle"; exit 1; }
rm -rf "$tmp"

start=$SECONDS
docker stop -t 10 "$NAME" >/dev/null
elapsed=$((SECONDS - start))
code=$(docker inspect -f '{{.State.ExitCode}}' "$NAME")
[ "$code" = 0 ] || { echo "exit code $code after docker stop"; docker logs "$NAME"; exit 1; }
[ $elapsed -lt 8 ] || { echo "docker stop took ${elapsed}s"; exit 1; }
echo "container check passed"
