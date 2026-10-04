# Contributing to rustid

Thank you for helping. Bug reports, fixes, documentation and tests are all
welcome. For a new feature or a large change, please open an issue first so
we can agree on the approach before you spend time on it. Report security
problems privately, as [SECURITY.md](SECURITY.md) describes.

## Setup

- Rust stable (`rust-toolchain.toml` selects it, with rustfmt and clippy).
- Docker, for the Postgres store tests and the container check.

## Before you open a pull request

    scripts/ci-local.sh

This runs everything CI runs: the repository checks, `cargo fmt --check`,
clippy with warnings denied, the tests on the memory and Postgres stores, the
release script tests and the container check. A pull request needs it green.

- Every change in behaviour comes with a test that fails without it.
- Match the surrounding code: its naming, its comments and its error
  handling.
- Keep a pull request to one change; update the docs and
  [CHANGELOG.md](CHANGELOG.md) (under `[Unreleased]`) when behaviour or
  configuration changes.

## Developer Certificate of Origin

Every commit must be signed off. By signing off you certify the
[Developer Certificate of Origin](https://developercertificate.org): that
you wrote the change, or otherwise have the right to submit it under the
project's licence.

Sign off with `-s`:

    git commit -s -m "Fix the thing"

This adds a trailer with your name and the email the commit is authored
with:

    Signed-off-by: Your Name <you@example.com>

CI checks every commit in a pull request. To fix a missing sign-off, amend
the last commit with `git commit --amend --no-edit -s`, or sign off a whole
branch with `git rebase --signoff main`, then force-push.

## Licence

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as in [README.md](README.md#license), without
any additional terms or conditions.
