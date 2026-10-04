#!/usr/bin/env bash
# Prints the workspace version from Cargo.toml. Given a tag, fails unless
# the tag is "v" followed by that version.
set -euo pipefail
root=${RELEASE_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
version=$(awk '
  /^\[/ { section = $0; next }
  section == "[workspace.package]" && /^version *= *"/ {
    sub(/^version *= *"/, ""); sub(/".*/, ""); print; exit
  }' "$root/Cargo.toml")
[ -n "$version" ] || { echo "no [workspace.package] version in $root/Cargo.toml" >&2; exit 1; }
if [ $# -gt 0 ] && [ "$1" != "v$version" ]; then
  echo "tag $1 does not match the workspace version $version (want v$version)" >&2
  exit 1
fi
echo "$version"
