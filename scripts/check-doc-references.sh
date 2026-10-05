#!/usr/bin/env bash
# Fails when a comment or doc cites, in backticks, a type or method that
# rustid's code doesn't have: a compound PascalCase name (`SomeTypeName`),
# a call (`Name()`, `Name(args)`, `Name().member`) or a member (`Type.Member`, `Type::member`) whose
# leading name never appears in the Rust code outside comments. Comments
# describe rustid in its own terms and cite its own items. Names that are
# legitimately not Rust identifiers go in scripts/doc-references.allow.
set -euo pipefail
root=${CHECK_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
cd "$root"
known=$(mktemp)
trap 'rm -f "$known"' EXIT
{
  git grep -hvE '^\s*//' -- '*.rs' | grep -oE '\b[A-Z][A-Za-z0-9]*\b' || true
  if [ -f scripts/doc-references.allow ]; then
    grep -vE '^\s*(#|$)' scripts/doc-references.allow || true
  fi
} | sort -u >"$known"
{
  git grep -nE '^\s*//' -- '*.rs' || true
  git grep -nE '`' -- '*.md' || true
} | perl -e '
  open my $f, "<", shift or die "known names: $!";
  my %known = map { chomp; ($_ => 1) } <$f>;
  my $status = 0;
  while (<STDIN>) {
    my ($loc, $text) = /^([^:]+:\d+):(.*)$/ or next;
    while ($text =~ /`([A-Z][A-Za-z0-9]*)((?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*)*)((?:\([^`()]*\)(?:(?:\.|::)[A-Za-z_][A-Za-z0-9_]*(?:\([^`()]*\))?)*)?)`/g) {
      my ($head, $member, $call) = ($1, $2, $3 // "");
      next unless $head =~ /[a-z0-9][A-Z]/ || $member ne "" || $call ne "";
      next if $known{$head};
      print "$loc: `$head$member$call`\n";
      $status = 1;
    }
  }
  exit $status;
' "$known"
echo "check-doc-references: clean"
