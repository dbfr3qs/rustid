#!/usr/bin/env python3
"""Writes the FAPI 2 conformance clients' keys and client list:
client1.jwk.json and client2.jwk.json (private RSA keys as JWKs, PS256,
which conformance/make-plans.py puts in plans/fapi2.json for the suite)
and clients.json (their public halves as JWK secrets). Keys are kept once
made; delete them to make new ones.

These are TEST-ONLY keys, committed so the conformance runs are
reproducible. They authenticate nothing outside conformance/: never reuse
them, or register their public halves anywhere real.

    python3 conformance/fapi2/make-keys.py
"""

import base64
import json
import pathlib

from cryptography.hazmat.primitives.asymmetric import rsa

HERE = pathlib.Path(__file__).parent
REDIRECT_URI = "https://localhost:8443/test/a/rustid-fapi2/callback"


def b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def private_jwk(kid: str) -> dict:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    p = key.private_numbers()
    return {
        "kty": "RSA", "use": "sig", "alg": "PS256", "kid": kid,
        "n": b64(p.public_numbers.n), "e": b64(p.public_numbers.e),
        "d": b64(p.d), "p": b64(p.p), "q": b64(p.q),
        "dp": b64(p.dmp1), "dq": b64(p.dmq1), "qi": b64(p.iqmp),
    }


def key(name: str, kid: str) -> dict:
    path = HERE / f"{name}.jwk.json"
    if not path.exists():
        path.write_text(json.dumps(private_jwk(kid), indent=2) + "\n")
    return json.loads(path.read_text())


def client(client_id: str, name: str, jwk: dict) -> dict:
    public = {k: jwk[k] for k in ("kty", "use", "alg", "kid", "n", "e")}
    return {
        "clientId": client_id,
        "clientName": name,
        "clientSecrets": [{"type": "JWK", "value": json.dumps(public)}],
        "allowedGrantTypes": ["authorization_code"],
        "allowedScopes": ["openid", "profile", "email", "address", "phone", "offline_access"],
        # The suite also sends the redirect URI with a query added (and
        # expects it kept); registered exactly, as rustid matches exactly
        # (the suite also sends it with these query parameters).
        "redirectUris": [REDIRECT_URI, REDIRECT_URI + "?dummy1=lorem&dummy2=ipsum"],
        "requirePkce": True,
        "requirePushedAuthorization": True,
        "requireDPoP": True,
        "requireConsent": False,
        "allowOfflineAccess": True,
        # FAPI2-SP-ID2-5.3.1.1-11: codes expire within 60 seconds.
        "authorizationCodeLifetime": 60,
    }


clients = [
    client("fapi2-conformance-client", "OIDF Conformance Suite FAPI2", key("client1", "fapi2-client1-key")),
    client("fapi2-conformance-client-2", "OIDF Conformance Suite FAPI2 (2)", key("client2", "fapi2-client2-key")),
]
(HERE / "clients.json").write_text(json.dumps(clients, indent=2) + "\n")
