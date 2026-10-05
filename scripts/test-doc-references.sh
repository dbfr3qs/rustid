#!/usr/bin/env bash
# Tests check-doc-references.sh against a fixture repository: it flags
# backticked citations of names the code doesn't have, in Rust comments
# and Markdown, and passes rustid's own items and allowlisted names.
set -euo pipefail
cd "$(dirname "$0")/.."
check=$PWD/scripts/check-doc-references.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }

g() { git -C "$tmp" -c user.name=t -c user.email=t@example.com -c commit.gpgsign=false "$@"; }
git init -q "$tmp"
mkdir -p "$tmp/src" "$tmp/docs" "$tmp/scripts"
cat >"$tmp/src/lib.rs" <<'EOF'
//! The session (`UserSession::sign_in`) and `Allowed()`.
/// Like `JsonWebToken.Claims` but ours.
pub struct UserSession;
// `ProfileDataRequestContext` was here.
/// `CryptoRandom.CreateUniqueId(32, Hex)` and `AsList().Get(key)`.
/// `UserSession.IsPersistent` and `int.TryParse(s)` and `Lookup(Key(k))`.
pub fn y() -> &'static str { "StringOnlyName" } // `StringOnlyName` here
/// `Option` and `Vec` are fine; so is `ETag` (no compound case), and
/// `UserSession::sign_in` and `x.len()`.
pub fn x() -> Option<Vec<u8>> { None }
EOF
echo 'See `NameValueCollection.GetValues`.' >"$tmp/docs/a.md"
printf '# test\nAllowed\n' >"$tmp/scripts/doc-references.allow"
g add -A && g commit -q -m fixture

status=0
out=$(CHECK_ROOT=$tmp "$check" 2>&1) || status=$?
[ "$status" = 1 ] || fail "exit $status with dangling citations, want 1"
for want in 'src/lib.rs:2: `JsonWebToken.Claims`' 'src/lib.rs:4: `ProfileDataRequestContext`' \
  'src/lib.rs:5: `CryptoRandom.CreateUniqueId(32, Hex)`' 'src/lib.rs:5: `AsList().Get(key)`' \
  'src/lib.rs:6: `UserSession.IsPersistent`' 'src/lib.rs:6: `int.TryParse(s)`' 'src/lib.rs:6: `Lookup(Key(k))`' \
  'src/lib.rs:7: `StringOnlyName`' 'docs/a.md:1: `NameValueCollection.GetValues`'; do
  grep -qF "$want" <<<"$out" || fail "did not report $want"
done
for name in 'UserSession::' Allowed Option Vec ETag 'x.len'; do
  if grep -q "\`$name" <<<"$out"; then fail "reported $name"; fi
done

sed -i -e 's/Like `JsonWebToken.Claims` but ours./A session./' -e '/ProfileDataRequestContext/d' -e '/CryptoRandom/d' -e '/IsPersistent/d' -e 's| // `StringOnlyName` here||' "$tmp/src/lib.rs"
echo 'See the docs.' >"$tmp/docs/a.md"
g commit -q -am fixed
CHECK_ROOT=$tmp "$check" >/dev/null 2>&1 || fail "still fails after the fix: $(CHECK_ROOT=$tmp "$check" 2>&1)"
outside=$(mktemp -d)
if CHECK_ROOT=$outside "$check" >/dev/null 2>&1; then fail "passes outside a git work tree"; fi
rmdir "$outside"

[ $failures = 0 ] || { echo "$failures doc reference check test(s) failed"; exit 1; }
echo "doc reference check tests passed"
