# SAML signature interoperability fixtures

Test vectors made by an independent XML signature and canonicalization implementation, from this repository's own test documents and test keys, by a generator kept outside the repository:

- `case-*.xml` and `case-*.digests`: canonicalization cases and the independent implementation's digests for them;
- `signed-*.xml`: SAML responses and AuthnRequests it signed (RSA, P-256, P-384, prefix lists, CRLF, CDATA, and several signing styles);
- `redirect-*.query`: redirect-binding queries signed the way the HTTP-Redirect binding signs them.

The `*.key.pem` files are **test-only keys** generated for these fixtures; never use them anywhere else.

`rustid-saml`'s tests verify these documents and reproduce the digests. The `oracle_*` examples in `rustid-saml` write documents for the other direction, where the independent implementation verifies rustid's output.
