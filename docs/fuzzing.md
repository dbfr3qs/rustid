# Fuzzing

rustid's parsers of untrusted input have libFuzzer targets. Each target's body is a plain function in `crates/rustid-fuzz`, and `fuzz/` wraps it for `cargo-fuzz`.

| Target | Covers |
|---|---|
| `jws` | Compact JWS decoding, claim access, and verification by the header's own key (client assertions, request objects, DPoP proofs, `id_token_hint`) |
| `form` | Form bodies and query strings; client secrets from the body and the Basic `Authorization` header |
| `xml` | The SAML XML DOM, exclusive and inclusive canonicalization, enveloped signature verification |
| `saml_redirect` | The redirect binding: query parsing, inflate, the XML, then the AuthnRequest, LogoutRequest and LogoutResponse readers |
| `saml_post` | The POST binding: form fields, base64, the XML, the readers |
| `certificate` | X.509 DER, PEM bundles (client CA roots), the forwarded-certificate header, SAML certificate text |
| `http` | The whole server in process (the default fixture profile, with admin and SAML on). The first byte picks a route: token, authorize, PAR, device, CIBA, introspection, SAML SSO (both bindings), admin clients, admin SAML service providers. A token or PAR input's first line, when it has one, is sent as the `DPoP` header, so DPoP proof validation is fuzzed through the endpoint. A panic is a finding, and so is a 500 on an OIDC or admin route |

## Running

    rustup toolchain install nightly --profile minimal && cargo install cargo-fuzz   # once
    scripts/fuzz.sh                 # every target, 60 s each
    scripts/fuzz.sh xml 600         # one target, 10 minutes

The runs use `-timeout=10 -rss_limit_mb=2048 -max_len=65536`, so a hang or a memory blow-up counts as a finding. A crash leaves its input in `fuzz/artifacts/<target>/`. Minimize it with `cargo +nightly fuzz tmin <target> <file>` and copy it to `fuzz/regressions/<target>/`, where `cargo test -p rustid-fuzz` (on stable, in CI) fails until it is fixed. The same test runs every target over its seeds (`fuzz/seeds/<target>/`).

The `http` target's server keeps state between inputs (admin writes, pushed requests, device and CIBA requests), as a real one does, and is rebuilt every 10,000 inputs. A finding can therefore depend on earlier inputs. If an artifact doesn't crash on its own, replay it after the corpus: `cargo +nightly fuzz run http corpus/http artifacts/http/<file> -- -runs=<corpus size + 1>`.

## Campaign (2026-10-03)

The runs used rustc 1.101.0-nightly (0abfedbc7 2026-10-02) and cargo-fuzz 0.13.2, with 60 s per target, on a loaded developer machine.

| Target | Executions | Coverage (edges) | Corpus | Findings |
|---|---|---|---|---|
| `jws` | 1,389,393 | 2,273 | 1,588 | none |
| `form` | 155,958 (after the fix) | 1,161 | 753 | 1: `parse_basic` sliced the `Authorization` value at byte 6 inside a multi-byte character and panicked. The same pattern in the IDN check of the request host was fixed too (9bc81cc). Over HTTP, header values are visible ASCII, so neither was reachable from the wire |
| `xml` | 105,255 | 3,090 | 976 | none |
| `saml_redirect` | 421,765 | 2,626 | 668 | none |
| `saml_post` | 394,686 | 2,476 | 687 | none |
| `certificate` | 100,713 | 2,686 | 771 | none |
| `http` | 34,325 (with the `DPoP` header) | 24,153 | 1,356 | none |
