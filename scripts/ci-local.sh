#!/usr/bin/env bash
# Runs the same checks as .github/workflows/ci.yml on a developer machine.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PG_CONTAINER=rustid-ci-postgres
cleanup() {
  if [ -n "${STARTED_PG:-}" ]; then docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

# Postgres for the store tests. A server
# named by TEST_POSTGRES_URL is used as is; otherwise a container is started.
if [ -z "${TEST_POSTGRES_URL:-}" ]; then
  echo "== postgres: starting container"
  PG_PORT="${TEST_POSTGRES_PORT:-55439}"
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --rm --name "$PG_CONTAINER" -e POSTGRES_PASSWORD=rustid \
    -p "127.0.0.1:$PG_PORT:5432" postgres:17-alpine >/dev/null
  STARTED_PG=1
  # The image's init phase runs a socket-only server; wait for TCP.
  for _ in $(seq 1 120); do
    docker exec "$PG_CONTAINER" pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && break
    sleep 0.5
  done
  export TEST_POSTGRES_URL="postgres://postgres:rustid@127.0.0.1:$PG_PORT/postgres"
fi

echo "== references: no upstream product names"
scripts/check-no-upstream-refs.sh

echo "== release scripts"
scripts/test-release-scripts.sh

echo "== rust: fmt, clippy, test"
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace

echo "== container: static image, readiness, health check, graceful stop"
scripts/container-check.sh

echo "== all checks passed"
