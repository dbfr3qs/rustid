#!/usr/bin/env bash
# Prints a version's section of CHANGELOG.md: the lines after its
# "## [VERSION]" heading, up to the next heading or the link references.
# Fails when the section is missing or empty.
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: $0 VERSION [CHANGELOG]" >&2; exit 2; }
root=${RELEASE_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
changelog=${2:-$root/CHANGELOG.md}
notes=$(awk -v v="$1" '
  index($0, "## [") == 1 { if (found) exit; found = (index($0, "## [" v "]") == 1); next }
  found && /^\[[^]]+\]: / { exit }
  found { print }' "$changelog" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}')
[ -n "$notes" ] || { echo "no notes for $1 in $changelog" >&2; exit 1; }
printf '%s\n' "$notes"
