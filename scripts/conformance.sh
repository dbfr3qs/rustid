#!/usr/bin/env bash
# Runs OpenID Foundation conformance test plans against rustid-server.
#
#   scripts/conformance.sh [plan ...]    # all plans when none are named
#   scripts/conformance.sh stop          # stop anything a failed run left
#
# Plans: oidcc-basic, implicit, hybrid, formpost-basic, formpost-implicit,
# formpost-hybrid, config, logout, frontchannel, backchannel,
# session-management (the default run); fapi2 and fapi2-final (the FAPI 2.0
# Security Profile ID2 and final, against a second rustid on
# https://localhost:9444, conformance/fapi2/rustid.toml); fapi-ciba
# (FAPI-CIBA ID1 in poll mode, against a third on https://localhost:9445,
# conformance/fapi-ciba/, with approver.py approving for the suite);
# fapi2-ms (FAPI 2.0 Message Signing: signed requests and JARM, against a
# fourth on https://localhost:9446, conformance/fapi2-ms/rustid.toml); dynamic
# and 3rdparty (dynamic client registration, against a fifth on
# https://localhost:9447, conformance/dynamic/rustid.toml; in the default run).
# Needs Docker (the suite's published images), git, python3 and network
# access the first time. rustid runs on https://localhost:9443 and the suite
# on https://localhost:8443, both on loopback only; results are exported to
# target/conformance/results. Exits non-zero when a plan has unexpected
# failures (conformance/expected/ lists the expected ones, per plan).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/target/conformance"
SUITE_DIR="$OUT/suite"
# The suite checkout that supplies run-test-plan.py.
SUITE_REPO="https://gitlab.com/openid/conformance-suite.git"
SUITE_COMMIT="${SUITE_COMMIT:-e89fb03947acc10127e1b7228a4724e3fe74813a}"
COMPOSE=(docker compose -p rustid-conformance -f "$ROOT/conformance/docker-compose.yml")

stop() {
  # KEEP=1 leaves everything running to look at (https://localhost:8443).
  if [ "${KEEP:-}" = "1" ] && [ "${1:-}" != "now" ]; then
    echo "KEEP=1: the suite and rustid are still running; scripts/conformance.sh stop ends them"
    return
  fi
  "${COMPOSE[@]}" down >/dev/null 2>&1 || true
  for pid in "$OUT/rustid.pid" "$OUT/rustid-fapi2.pid" "$OUT/rustid-fapi-ciba.pid" "$OUT/rustid-fapi2-ms.pid" "$OUT/rustid-dynamic.pid" "$OUT/approver.pid"; do
    if [ -f "$pid" ]; then
      kill "$(cat "$pid")" 2>/dev/null || true
      rm -f "$pid"
    fi
  done
}

if [ "${1:-}" = "stop" ]; then
  stop now
  exit 0
fi

declare -A VARIANTS=(
  [oidcc-basic]="oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
  [logout]="oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]"
  [frontchannel]="oidcc-frontchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]"
  [backchannel]="oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]"
  [session-management]="oidcc-session-management-certification-test-plan[response_type=code][client_registration=static_client]"
  [implicit]="oidcc-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
  [hybrid]="oidcc-hybrid-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
  [formpost-basic]="oidcc-formpost-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
  [formpost-implicit]="oidcc-formpost-implicit-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
  [formpost-hybrid]="oidcc-formpost-hybrid-certification-test-plan[server_metadata=discovery][client_registration=static_client]"
  [config]="oidcc-config-certification-test-plan"
  [fapi2]="fapi2-security-profile-id2-test-plan[fapi_profile=plain_fapi][authorization_request_type=simple][openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop]"
  [fapi2-final]="fapi2-security-profile-final-test-plan[fapi_profile=plain_fapi][authorization_request_type=simple][openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop]"
  [fapi2-ms]="fapi2-message-signing-final-test-plan[fapi_profile=plain_fapi][authorization_request_type=simple][openid=openid_connect][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_request_method=signed_non_repudiation][fapi_response_mode=jarm]"
  [dynamic]="oidcc-dynamic-certification-test-plan[response_type=code]"
  [3rdparty]="oidcc-3rdparty-init-login-certification-test-plan[response_type=code]"
  [fapi-ciba]="fapi-ciba-id1-test-plan[client_auth_type=private_key_jwt][fapi_ciba_profile=plain_fapi][ciba_mode=poll][client_registration=static_client]"
)
PLANS=("$@")
if [ ${#PLANS[@]} -eq 0 ]; then
  PLANS=(oidcc-basic implicit hybrid formpost-basic formpost-implicit formpost-hybrid config logout frontchannel backchannel session-management dynamic 3rdparty)
fi
for plan in "${PLANS[@]}"; do
  [ -n "${VARIANTS[$plan]:-}" ] || { echo "unknown plan: $plan" >&2; exit 2; }
done

mkdir -p "$OUT/results"
stop now
trap stop EXIT

echo "== certificates and rustid-server"
cd "$ROOT"
cargo build -q -p rustid-server -p rustid-demo
./target/debug/rustid-demo certs --out "$OUT" --host localhost --host 127.0.0.1 >/dev/null
./target/debug/rustid-server --config conformance/rustid.toml >"$OUT/rustid.log" 2>&1 &
echo $! >"$OUT/rustid.pid"
FAPI2=0
CIBA=0
FAPI2_MS=0
DYNAMIC=0
for plan in "${PLANS[@]}"; do
  case "$plan" in fapi2|fapi2-final) FAPI2=1 ;; fapi-ciba) CIBA=1 ;; fapi2-ms) FAPI2_MS=1 ;; dynamic|3rdparty) DYNAMIC=1 ;; esac
done
if [ "$FAPI2" = 1 ]; then
  ./target/debug/rustid-server --config conformance/fapi2/rustid.toml >"$OUT/rustid-fapi2.log" 2>&1 &
  echo $! >"$OUT/rustid-fapi2.pid"
fi
if [ "$CIBA" = 1 ]; then
  python3 conformance/fapi-ciba/approver.py >"$OUT/approver.log" 2>&1 &
  echo $! >"$OUT/approver.pid"
  ./target/debug/rustid-server --config conformance/fapi-ciba/rustid.toml >"$OUT/rustid-fapi-ciba.log" 2>&1 &
  echo $! >"$OUT/rustid-fapi-ciba.pid"
fi
if [ "$FAPI2_MS" = 1 ]; then
  ./target/debug/rustid-server --config conformance/fapi2-ms/rustid.toml >"$OUT/rustid-fapi2-ms.log" 2>&1 &
  echo $! >"$OUT/rustid-fapi2-ms.pid"
fi
if [ "$DYNAMIC" = 1 ]; then
  ./target/debug/rustid-server --config conformance/dynamic/rustid.toml >"$OUT/rustid-dynamic.log" 2>&1 &
  echo $! >"$OUT/rustid-dynamic.pid"
fi

echo "== the conformance suite"
if [ ! -d "$SUITE_DIR/.git" ]; then
  git clone -q "$SUITE_REPO" "$SUITE_DIR"
fi
git -C "$SUITE_DIR" fetch -q --depth 1 origin "$SUITE_COMMIT" 2>/dev/null || true
git -C "$SUITE_DIR" checkout -q "$SUITE_COMMIT"
if [ ! -x "$OUT/venv/bin/python" ]; then
  python3 -m venv "$OUT/venv"
  "$OUT/venv/bin/pip" install -q -r "$SUITE_DIR/scripts/requirements.txt"
fi
"${COMPOSE[@]}" up -d >/dev/null

wait_for() {
  for _ in $(seq 1 180); do
    curl -skf "$1" >/dev/null && return 0
    sleep 1
  done
  echo "$1 did not come up" >&2
  return 1
}
wait_for https://localhost:9443/.well-known/openid-configuration
if [ "$FAPI2" = 1 ]; then
  wait_for https://localhost:9444/.well-known/openid-configuration
fi
if [ "$CIBA" = 1 ]; then
  wait_for https://localhost:9445/.well-known/openid-configuration
fi
if [ "$FAPI2_MS" = 1 ]; then
  wait_for https://localhost:9446/.well-known/openid-configuration
fi
if [ "$DYNAMIC" = 1 ]; then
  wait_for https://localhost:9447/.well-known/openid-configuration
fi
wait_for https://localhost:8443/api/runner/available

status=0
for plan in "${PLANS[@]}"; do
  echo "== plan: $plan"
  CONFORMANCE_SERVER=https://localhost:8443/ \
  CONFORMANCE_SERVER_MTLS=https://localhost:8444/ \
  CONFORMANCE_DEV_MODE=1 \
    "$OUT/venv/bin/python" "$SUITE_DIR/scripts/run-test-plan.py" \
      --expected-failures-file "$ROOT/conformance/expected/$plan-failures.json" \
      --expected-skips-file "$ROOT/conformance/expected/$plan-skips.json" \
      --export-dir "$OUT/results" --verbose --no-parallel \
      "${VARIANTS[$plan]}" "$ROOT/conformance/plans/$plan.json" || status=1
done
exit $status
