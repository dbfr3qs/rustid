#!/usr/bin/env bash
# Time-boxed libFuzzer campaigns over rustid's untrusted-input parsers.
#   scripts/fuzz.sh                 # every target, 60 s each
#   scripts/fuzz.sh xml 600         # one target, 10 minutes
# Needs nightly and cargo-fuzz:
#   rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz
# A crash leaves its input in fuzz/artifacts/<target>/; minimize it with
# `cargo +nightly fuzz tmin <target> <file>`, copy it to
# fuzz/regressions/<target>/ and fix it test-first (cargo test -p rustid-fuzz).
set -euo pipefail
cd "$(dirname "$0")/../fuzz"
SECONDS_EACH=${2:-60}
if [ -n "${1:-}" ]; then
  TARGETS=("$1")
else
  # A failing `cargo fuzz list` (no nightly, no cargo-fuzz) must fail the run,
  # not run nothing and exit 0.
  list=$(cargo +nightly fuzz list) || { echo "fuzz.sh: cargo +nightly fuzz list failed" >&2; exit 1; }
  mapfile -t TARGETS <<<"$list"
  [ -n "${TARGETS[0]:-}" ] || { echo "fuzz.sh: no fuzz targets" >&2; exit 1; }
fi
status=0
for t in "${TARGETS[@]}"; do
  mkdir -p "corpus/$t"
  echo "== $t (${SECONDS_EACH}s)"
  cargo +nightly fuzz run "$t" "corpus/$t" "seeds/$t" -- \
    -max_total_time="$SECONDS_EACH" -timeout=10 -rss_limit_mb=2048 -max_len=65536 \
    || { echo "!! $t found a crash: see fuzz/artifacts/$t"; status=1; }
done
exit $status
