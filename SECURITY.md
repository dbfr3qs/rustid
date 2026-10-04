# Security policy

## Supported versions

rustid is before 1.0: security fixes go into the latest release only, and
there are no backports.

| Version | Supported |
|---|---|
| latest 0.x release | yes |
| older | no |

## Reporting a vulnerability

Report vulnerabilities privately, through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**. Please do not open a
public issue, pull request or discussion for a vulnerability.

A useful report includes:

- the version (`rustid-server --version`) or commit;
- the configuration that matters (with secrets removed);
- the requests that show the problem, or a test that reproduces it;
- what an attacker gains.

## What to expect

- An acknowledgement within 7 days.
- An assessment, and a fix or a plan for one, within 30 days.
- A release with the fix, a GitHub security advisory, and credit in it
  unless you would rather not be named. Please keep the details private
  until the advisory is published.
