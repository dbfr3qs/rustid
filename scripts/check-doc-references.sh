#!/usr/bin/env bash
# Fails when a comment or doc cites, in backticks, a type or method that
# rustid's code doesn't have:
# - a compound PascalCase name (`SomeTypeName`), a call (`Name()`,
#   `Name(args)`) or a path (`Name::item`) whose leading name never appears
#   in the Rust code (outside comments and string literals);
# - a PascalCase member after a dot (`anything.Member`), which Rust's
#   snake_case members never are.
# Comments describe rustid in its own terms and cite its own items. Names
# that are legitimately not Rust identifiers go in
# scripts/doc-references.allow.
set -euo pipefail
root=${CHECK_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
cd "$root"
git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
  || { echo "check-doc-references: $root is not a git work tree" >&2; exit 2; }
allow=scripts/doc-references.allow
[ -f "$allow" ] || allow=/dev/null
git ls-files -z -- '*.rs' '*.md' | perl -0 -e '
  my $allow = shift;
  my @files = map { chomp; $_ } <STDIN>;
  $/ = "\n";
  my (%known, @lines);
  open my $a, "<", $allow or die "$allow: $!";
  while (<$a>) { s/^\s+|\s+$//g; $known{$_} = 1 if $_ ne "" && !/^#/ }
  for my $file (@files) {
    open my $f, "<", $file or die "$file: $!";
    my $n = 0;
    while (my $line = <$f>) {
      $n++;
      chomp $line;
      if ($file =~ /\.md$/) { push @lines, ["$file:$n", $line]; next }
      (my $code = $line) =~ s/"(?:[^"\\]|\\.)*"/""/g;
      my $comment = "";
      if ((my $i = index($code, "//")) >= 0) {
        $comment = substr($code, $i);
        $code = substr($code, 0, $i);
        # The comment as written, string literals included.
        my $j = index($line, substr($comment, 0, 3));
        $comment = substr($line, $j) if $j >= 0;
      }
      $known{$_} = 1 for $code =~ /\b([A-Z][A-Za-z0-9_]*)\b/g;
      push @lines, ["$file:$n", $comment] if $comment ne "";
    }
  }
  my $status = 0;
  for (@lines) {
    my ($loc, $text) = @$_;
    while ($text =~ /`([^`]+)`/g) {
      my $cite = $1;
      next unless $cite =~ /^([A-Za-z_][A-Za-z0-9_]*)(.*)$/;
      my ($head, $rest) = ($1, $2);
      my $foreign_member = $rest =~ /\.[A-Z]/;
      my $foreign_head = $head =~ /^[A-Z]/
        && ($head =~ /[a-z0-9][A-Z]/ || $rest =~ /^(?:\.|\(|::)/)
        && !$known{$head};
      next unless $foreign_member || $foreign_head;
      print "$loc: `$cite`\n";
      $status = 1;
    }
  }
  exit $status;
' "$allow"
echo "check-doc-references: clean"
