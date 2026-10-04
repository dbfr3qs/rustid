#!/usr/bin/env bash
# Tests the release scripts against fixtures: release-version.sh (the tag
# matches the workspace version), release-notes.sh (a version's CHANGELOG
# section) and check-dco.sh (every commit signed off by its author).
set -euo pipefail
cd "$(dirname "$0")/.."
scripts=$PWD/scripts
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
ok() { "$@" >/dev/null 2>&1 || fail "expected success: $*"; }
refused() { if "$@" >/dev/null 2>&1; then fail "expected failure: $*"; fi; }

cat >"$tmp/Cargo.toml" <<'EOF'
[workspace]
members = ["crates/*"]

[workspace.package]
edition = "2024"
version = "1.2.3"

[workspace.dependencies]
serde = { version = "1" }
EOF
cat >"$tmp/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

## [1.2.3] - 2026-01-02

### Added

- The new thing.

## [1.2.2] - 2026-01-01

- The old thing.

## [1.2.1] - 2025-12-31

## [1.2.0] - 2025-12-30

- The first thing.

[1.2.3]: https://example.com/1.2.3
EOF
export RELEASE_ROOT=$tmp

# release-version.sh
[ "$("$scripts/release-version.sh")" = 1.2.3 ] || fail "release-version.sh does not print 1.2.3"
ok "$scripts/release-version.sh" v1.2.3
refused "$scripts/release-version.sh" v1.2.4
refused "$scripts/release-version.sh" 1.2.3
refused "$scripts/release-version.sh" v1.2.3.1

# release-notes.sh
notes=$("$scripts/release-notes.sh" 1.2.3) || fail "release-notes.sh 1.2.3 failed"
[ "$notes" = "$(printf '### Added\n\n- The new thing.')" ] || fail "release-notes.sh 1.2.3 printed: $notes"
[ "$("$scripts/release-notes.sh" 1.2.0 2>/dev/null)" = "- The first thing." ] || fail "release-notes.sh 1.2.0 includes the link references"
refused "$scripts/release-notes.sh" 9.9.9
refused "$scripts/release-notes.sh" 1.2.1
refused "$scripts/release-notes.sh" 1.2

# check-dco.sh
repo=$tmp/repo
git init -q -b main "$repo"
in_repo() { (cd "$repo" && "$@"); }
g() { git -C "$repo" -c user.name="Ada Lovelace" -c user.email=ada@example.com -c commit.gpgsign=false "$@"; }
g commit -q --allow-empty -m base
base=$(g rev-parse HEAD)
g commit -q --allow-empty -s -m signed
signed=$(g rev-parse HEAD)
ok in_repo "$scripts/check-dco.sh" "$base" "$signed"
refused in_repo "$scripts/check-dco.sh" deadbeefdeadbeef "$signed"
refused in_repo "$scripts/check-dco.sh" 0000000000000000000000000000000000000000 "$signed"
g commit -q --allow-empty -m "unsigned"
unsigned=$(g rev-parse --short HEAD)
out=$(cd "$repo" && "$scripts/check-dco.sh" "$base" HEAD 2>&1) && fail "check-dco.sh passed an unsigned commit"
grep -q "$unsigned" <<<"$out" || fail "check-dco.sh did not name $unsigned: $out"
g reset -q --hard "$signed"
g commit -q --allow-empty -m "other" -m "Signed-off-by: Ada Lovelace <someone@example.com>"
other=$(g rev-parse --short HEAD)
out=$(cd "$repo" && "$scripts/check-dco.sh" "$base" HEAD 2>&1) && fail "check-dco.sh passed a sign-off by another email"
grep -q "$other" <<<"$out" || fail "check-dco.sh did not name $other: $out"
g reset -q --hard "$signed"
g checkout -q -b side
g commit -q --allow-empty -s -m side
g checkout -q main
g merge -q --no-ff --no-edit side
ok in_repo "$scripts/check-dco.sh" "$base" HEAD

[ $failures = 0 ] || { echo "$failures release script test(s) failed"; exit 1; }
echo "release script tests passed"
