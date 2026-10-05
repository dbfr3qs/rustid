#!/usr/bin/env bash
# Fails when a tracked text file names the upstream product this project
# was once compared with, its platform, or the private parity harness, or
# cites an upstream type or method name. rustid is described on its own
# terms. Lines are also checked joined, so a phrase split by a line break
# is caught.
set -euo pipefail
cd "$(dirname "$0")/.."
EXCLUDE=(':!scripts/check-no-upstream-refs.sh')
WORDS='duende|identity ?server|reference[ _-]?host|samloracle|efexport|(^|[^a-z0-9])\.net\b|dotnet|asp\.net|microsoft($|[^o])|\btest ui\b|\bdifferential\b|\bparity\b|\bported\b'
CITES='`I[A-Z][a-z][A-Za-z]*(\.[A-Za-z]+)?`|`[A-Za-z.]*[a-z]Async`'
status=0
if git grep -nIiE "$WORDS" -- . "${EXCLUDE[@]}"; then status=1; fi
if git grep -nIE "$CITES" -- . "${EXCLUDE[@]}"; then status=1; fi
# A phrase split across two comment lines.
if ! git ls-files -z -- . "${EXCLUDE[@]}" | python3 -c '
import re, sys
bad = False
for name in sys.stdin.read().split("\0"):
    if not name:
        continue
    try:
        text = open(name, encoding="utf-8").read()
    except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
        continue
    joined = re.sub(r"\n\s*(?://[/!]?|#|--)?\s*", " ", text)
    if re.search(r"reference[ _-]+host|\btest +ui\b", joined, re.I):
        print(name + ": a split upstream phrase")
        bad = True
sys.exit(1 if bad else 0)
'; then status=1; fi
if [ "$status" -ne 0 ]; then
  echo "check-no-upstream-refs: the lines above name upstream sources" >&2
  exit 1
fi
echo "check-no-upstream-refs: clean"
