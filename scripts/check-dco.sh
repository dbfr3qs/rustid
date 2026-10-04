#!/usr/bin/env bash
# Fails when a commit in BASE..HEAD (merges aside) has no
# "Signed-off-by:" trailer with its author's email (the Developer
# Certificate of Origin, CONTRIBUTING.md). Names each such commit.
set -euo pipefail
[ $# -eq 2 ] || { echo "usage: $0 BASE HEAD" >&2; exit 2; }
status=0
for commit in $(git rev-list --no-merges "$1..$2"); do
  email=$(git log -1 --format='%ae' "$commit")
  if ! git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$commit" \
      | grep -qiF "<$email>"; then
    echo "$(git log -1 --format='%h %s' "$commit"): no Signed-off-by for <$email>" >&2
    status=1
  fi
done
[ $status = 0 ] || echo "Sign off with git commit -s (CONTRIBUTING.md); fix a branch with git rebase --signoff <base>." >&2
exit $status
