#!/usr/bin/env python3
"""Writes conformance/plans/*.json: the suite's configuration for each test
plan, with browser automation for rustid's interactive reference UI.

Run it after changing clients, URLs or the UI's pages:

    python3 conformance/make-plans.py
"""

import json
import pathlib

RUSTID = "https://localhost:9443"
# The FAPI 2 instance (conformance/fapi2/rustid.toml).
RUSTID_FAPI2 = "https://localhost:9444"
# FAPI 2.0 final: issuer-only client assertion audiences, which ID2 forbids.
RUSTID_FAPI2_FINAL = "https://localhost:9449"
# The FAPI-CIBA instance (conformance/fapi-ciba/rustid.toml).
RUSTID_CIBA = "https://localhost:9445"
# The FAPI 2 message signing instance (conformance/fapi2-ms/rustid.toml).
RUSTID_FAPI2_MS = "https://localhost:9446"
# The dynamic registration instance (conformance/dynamic/rustid.toml).
RUSTID_DYNAMIC = "https://localhost:9447"
HERE = pathlib.Path(__file__).parent


def login_task(base: str) -> dict:
    """The reference UI's login form, filled as alice."""
    return {
        "task": "Login",
        "optional": True,
        "match": f"{base}/Account/Login*",
        "commands": [
            ["text", "id", "username", "alice", "optional"],
            ["text", "id", "password", "alice", "optional"],
            ["click", "xpath", "//button[@value='login']"],
        ],
    }


def consent_task(base: str) -> dict:
    """`prompt=consent` shows the consent page: allow everything."""
    return {
        "task": "Consent",
        "optional": True,
        "match": f"{base}/consent*",
        "commands": [["click", "xpath", "//button[@value='yes']"]],
    }


LOGIN = login_task(RUSTID)
CONSENT = consent_task(RUSTID)
CALLBACK = {
    "task": "Verify Complete",
    "match": "*/test/*/callback*",
    "commands": [["wait", "id", "submission_complete", 10]],
}
AUTHORIZE = {"match": f"{RUSTID}/connect/authorize*", "tasks": [LOGIN, CONSENT, CALLBACK]}

# RP-initiated logout: confirm when asked, then back to the suite.
CONFIRM = {
    "task": "Confirm sign-out",
    "optional": True,
    "match": f"{RUSTID}/Account/Logout*",
    "commands": [["click", "xpath", "//button[@type='submit']", "optional"]],
}
# The signed-out page returns to the client by itself once the
# front-channel iframe has loaded.
BACK_TO_CLIENT = {
    "task": "Wait for the redirect back",
    "optional": True,
    "match": f"{RUSTID}/Account/Logout*",
    "commands": [["wait", "contains", "/test/*/post", 10]],
}
POST_LOGOUT = {"task": "Verify Complete", "match": "*/test/*/post*"}
END_SESSION = {
    "match": f"{RUSTID}/connect/endsession*",
    "tasks": [CONFIRM, BACK_TO_CLIENT, POST_LOGOUT],
}


def error_page(start: str, base: str = RUSTID) -> dict:
    """The browser starts at `start` and must end on rustid's error page,
    whose screenshot fills the test's image placeholder."""
    return {
        "comment": "expect an error page",
        "match": f"{base}{start}*",
        "tasks": [
            {
                "task": "Expect error page",
                "match": f"{base}/home/error*",
                "commands": [
                    ["wait", "xpath", "//*", 10, "could not be completed", "update-image-placeholder"]
                ],
            }
        ],
    }


def login_screenshot() -> dict:
    """A second login whose page fills the test's image placeholder."""
    login = dict(LOGIN)
    login["commands"] = [
        ["wait", "xpath", "//*", 10, "Sign in", "update-image-placeholder-optional"],
        *LOGIN["commands"],
    ]
    return {"match": f"{RUSTID}/connect/authorize*", "tasks": [login, CONSENT, CALLBACK]}


def signed_out(confirm: bool) -> dict:
    """Logout without a way back to the client: rustid's signed-out page
    fills the image placeholder."""
    tasks = [CONFIRM] if confirm else []
    tasks.append(
        {
            "task": "Expect signed-out page",
            "match": f"{RUSTID}/Account/Logout*",
            "commands": [
                ["wait", "xpath", "//*", 10, "signed out", "update-image-placeholder"]
            ],
        }
    )
    return {"match": f"{RUSTID}/connect/endsession*", "tasks": tasks}


SUITE = "https://localhost:8443/test/a/*"


def session_check(first: bool) -> dict:
    """The suite's session check page: its RP iframe asks rustid's check
    session iframe, then moves the page on to the result."""
    step = "" if first else "second_"
    return {
        "match": f"{SUITE}/{step}session_verify*",
        "tasks": [
            {
                "task": "Check the session" + ("" if first else " again"),
                "match": f"*/{step}session_verify*",
                "commands": [["wait", "contains", f"{step}session_result", 15]],
            },
            {"task": "Verify Complete", "match": f"*/{step}session_result*"},
        ],
    }


def plan(
    alias: str,
    description: str,
    client: dict,
    overrides: dict,
    browser=None,
    base: str = RUSTID,
    **extra,
) -> dict:
    config = {
        "alias": alias,
        "description": description,
        "server": {"discoveryUrl": f"{base}/.well-known/openid-configuration"},
        "client": client,
        "browser": browser if browser is not None else [AUTHORIZE, END_SESSION],
        "override": {name: {"browser": browser} for name, browser in overrides.items()},
    }
    config.update(extra)
    return config


# At least 32 bytes: some tests sign with the secret (HS256).
SECRET = "conformance-secret-long-enough-for-hs256"


def secret(client_id: str, value: str = SECRET) -> dict:
    return {"client_id": client_id, "client_secret": value}


POST = secret("conformance-suite-post", "conformance-post-secret-long-enough-for-hs256")
OIDCC_ERRORS = {
    name: [error_page("/connect/authorize")]
    for name in [
        "oidcc-ensure-registered-redirect-uri",
        "oidcc-ensure-redirect-uri-in-authorization-request",
        "oidcc-redirect-uri-query-added",
        "oidcc-redirect-uri-query-mismatch",
        "oidcc-response-type-missing",
    ]
}
# Implicit and hybrid: a request without a nonce is refused on rustid's
# error page (the redirect URI isn't trusted with an error then).
NONCE_REQUIRED = {"oidcc-ensure-request-without-nonce-fails": [error_page("/connect/authorize")]}
OIDCC_LOGINS = {name: [login_screenshot()] for name in ["oidcc-prompt-login", "oidcc-max-age-1"]}

# Logout tests where rustid doesn't return to the client: it asks (no
# client identified) or just signs out, and shows its signed-out page.
LOGOUT_SIGNED_OUT = {
    "oidcc-rp-initiated-logout-bad-post-logout-redirect-uri": [AUTHORIZE, signed_out(False)],
    "oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri": [AUTHORIZE, signed_out(False)],
    "oidcc-rp-initiated-logout-modified-id-token-hint": [AUTHORIZE, signed_out(True)],
    "oidcc-rp-initiated-logout-bad-id-token-hint": [AUTHORIZE, signed_out(True)],
    "oidcc-rp-initiated-logout-no-id-token-hint": [AUTHORIZE, signed_out(True)],
    "oidcc-rp-initiated-logout-no-params": [AUTHORIZE, signed_out(True)],
    "oidcc-rp-initiated-logout-no-post-logout-redirect-uri": [AUTHORIZE, signed_out(False)],
    "oidcc-rp-initiated-logout-only-state": [AUTHORIZE, signed_out(True)],
}

def fapi2_client(
    name: str, client_id: str, description: str, alias: str = "rustid-fapi2"
) -> dict:
    """A FAPI 2 client as the suite holds it: its private key (made by
    conformance/fapi2/make-keys.py)."""
    jwk = json.loads((HERE / "fapi2" / f"{name}.jwk.json").read_text())
    return {
        "client_name": description,
        "redirect_uri": f"https://localhost:8443/test/a/{alias}/callback",
        "client_id": client_id,
        # offline_access too, so the refresh-token module has one to test
        # (otherwise the module is skipped).
        "scope": "openid profile offline_access",
        "jwks": {"keys": [jwk]},
    }


FAPI2 = "fapi2-security-profile-id2-"


def once(entry: dict) -> dict:
    """`entry` for the first matching visit only (the suite's match-limit)."""
    return {**entry, "match-limit": 1}


def fapi2_browser(base: str, prefix: str) -> tuple:
    """A FAPI 2 instance's browser automation at `base`, and the overrides
    for the modules that need a person to drive them (error pages, PAR reuse, cancelling),
    named with the plan's module `prefix`."""
    authorize = {
        "match": f"{base}/connect/authorize*",
        "tasks": [login_task(base), consent_task(base), CALLBACK],
    }
    error = error_page("/connect/authorize", base)
    # Only the login page: the module sends the same request_uri again
    # before anyone signs in.
    login_page_only = {
        "match": f"{base}/connect/authorize*",
        "tasks": [
            {
                "task": "Show the login page without signing in",
                "match": f"{base}/Account/Login*",
                "commands": [["wait", "id", "username", 10]],
            }
        ],
    }
    # The user cancels on the login page; rustid returns access_denied.
    cancel = {
        "match": f"{base}/connect/authorize*",
        "tasks": [
            {
                "task": "Cancel",
                "match": f"{base}/Account/Login*",
                "commands": [["click", "xpath", "//button[@value='cancel']"]],
            },
            CALLBACK,
        ],
    }
    overrides = {
        # rustid's error page.
        prefix + "ensure-unsigned-authorization-request-without-using-par-fails": [error],
        prefix + "par-attempt-to-use-request_uri-for-different-client": [error],
        prefix + "par-attempt-to-use-expired-request_uri": [error],
        # Signs in once, then the reused request_uri is refused.
        prefix + "par-attempt-reuse-request_uri": [once(authorize), error],
        # The login page twice, signing in the second time.
        prefix + "par-ensure-reused-request-uri-prior-to-auth-completion-succeeds": [
            once(login_page_only),
            authorize,
        ],
        prefix + "user-rejects-authentication": [cancel],
    }
    return authorize, overrides


FAPI2_AUTHORIZE, FAPI2_OVERRIDES = fapi2_browser(RUSTID_FAPI2, FAPI2)
# The same modules in the final profile's plan.
FAPI2_FINAL_AUTHORIZE, FAPI2_FINAL_OVERRIDES = fapi2_browser(
    RUSTID_FAPI2_FINAL, "fapi2-security-profile-final-"
)
# The message signing plan reuses the final profile's modules.
FAPI2_MS_AUTHORIZE, FAPI2_MS_OVERRIDES = fapi2_browser(
    RUSTID_FAPI2_MS, "fapi2-security-profile-final-"
)

# Dynamic registration: the suite registers its own clients at 9447.
DYNAMIC_AUTHORIZE = {
    "match": f"{RUSTID_DYNAMIC}/connect/authorize*",
    "tasks": [login_task(RUSTID_DYNAMIC), consent_task(RUSTID_DYNAMIC), CALLBACK],
}
# The registration URI modules want a screenshot of the login page (which
# would show the client's logo, policy or terms link); the test ends once
# it is uploaded, without signing in.
DYNAMIC_LOGIN_PAGE = {
    name: [
        {
            "match": f"{RUSTID_DYNAMIC}/connect/authorize*",
            "tasks": [
                {
                    "task": "Screenshot the login page",
                    "match": f"{RUSTID_DYNAMIC}/Account/Login*",
                    "commands": [["wait", "xpath", "//*", 10, "Sign in", "update-image-placeholder"]],
                }
            ],
        }
    ]
    for name in ["oidcc-registration-logo-uri", "oidcc-registration-policy-uri", "oidcc-registration-tos-uri"]
}
DYNAMIC_ERRORS = {
    name: [error_page("/connect/authorize", RUSTID_DYNAMIC)]
    for name in [
        "oidcc-ensure-redirect-uri-in-authorization-request",
        "oidcc-redirect-uri-query-added",
        "oidcc-redirect-uri-query-mismatch",
    ]
}


def ciba_client(n: int, client_id: str) -> dict:
    """A FAPI-CIBA client as the suite holds it: the FAPI 2 client's key
    (private_key_jwt and request objects) and login hint alice."""
    jwk = json.loads((HERE / "fapi2" / f"client{n}.jwk.json").read_text())
    return {
        "client_id": client_id,
        # offline_access too, so the refresh-token module has one to test.
        "scope": "openid profile offline_access",
        "hint_type": "login_hint",
        "hint_value": "alice",
        "jwks": {"keys": [jwk]},
    }


def ciba_mtls(n: int) -> dict:
    """The test-only client certificate the suite presents (FAPI-CIBA binds
    tokens to it)."""
    read = lambda kind: (HERE / "fapi-ciba" / f"client{n}.{kind}.pem").read_text()
    return {"cert": read("cert"), "key": read("key")}


PLANS = {
    "oidcc-basic": plan(
        "rustid-oidcc",
        "rustid OIDC core",
        secret("conformance-suite"),
        {**OIDCC_ERRORS, **OIDCC_LOGINS},
        client2=POST,
        client_secret_post=POST,
    ),
    "logout": plan(
        "rustid-logout",
        "rustid RP-initiated logout",
        secret("conformance-logout"),
        LOGOUT_SIGNED_OUT,
    ),
    "frontchannel": plan(
        "rustid-frontchannel",
        "rustid front-channel logout",
        secret("conformance-frontchannel"),
        {},
    ),
    "backchannel": plan(
        "rustid-backchannel",
        "rustid back-channel logout",
        secret("conformance-backchannel"),
        {},
    ),
    "session-management": plan(
        "rustid-session",
        "rustid session management",
        secret("conformance-session"),
        {},
        browser=[AUTHORIZE, END_SESSION, session_check(False), session_check(True)],
    ),
    "implicit": plan(
        "rustid-implicit",
        "rustid OIDC implicit",
        secret("conformance-implicit"),
        {**OIDCC_ERRORS, **OIDCC_LOGINS, **NONCE_REQUIRED},
        client2=secret("conformance-implicit-2", POST["client_secret"]),
    ),
    "hybrid": plan(
        "rustid-hybrid",
        "rustid OIDC hybrid",
        secret("conformance-hybrid"),
        {**OIDCC_ERRORS, **OIDCC_LOGINS, **NONCE_REQUIRED},
        client2=secret("conformance-hybrid-post", POST["client_secret"]),
        client_secret_post=secret("conformance-hybrid-post", POST["client_secret"]),
    ),
    "formpost-basic": plan(
        "rustid-formpost",
        "rustid OIDC form_post (code)",
        secret("conformance-suite"),
        {**OIDCC_ERRORS, **OIDCC_LOGINS},
        client2=POST,
        client_secret_post=POST,
    ),
    "formpost-implicit": plan(
        "rustid-formpost-implicit",
        "rustid OIDC form_post (implicit)",
        secret("conformance-implicit"),
        {**OIDCC_ERRORS, **OIDCC_LOGINS, **NONCE_REQUIRED},
        client2=secret("conformance-implicit-2", POST["client_secret"]),
    ),
    "formpost-hybrid": plan(
        "rustid-formpost-hybrid",
        "rustid OIDC form_post (hybrid)",
        secret("conformance-hybrid"),
        {**OIDCC_ERRORS, **OIDCC_LOGINS, **NONCE_REQUIRED},
        client2=secret("conformance-hybrid-post", POST["client_secret"]),
        client_secret_post=secret("conformance-hybrid-post", POST["client_secret"]),
    ),
    "config": plan(
        "rustid-config",
        "rustid OIDC discovery",
        secret("conformance-suite"),
        {},
    ),
    "fapi2": plan(
        "rustid-fapi2",
        "rustid FAPI 2.0 Security Profile",
        fapi2_client("client1", "fapi2-conformance-client", "OIDF Conformance Suite"),
        FAPI2_OVERRIDES,
        browser=[FAPI2_AUTHORIZE],
        base=RUSTID_FAPI2,
        client2=fapi2_client("client2", "fapi2-conformance-client-2", "OIDF Conformance Suite 2"),
        resource={"resourceUrl": f"{RUSTID_FAPI2}/fapi2/resource"},
        waitTimeoutSeconds=30,
    ),
    "fapi2-final": plan(
        "rustid-fapi2",
        "rustid FAPI 2.0 Security Profile (final)",
        fapi2_client("client1", "fapi2-conformance-client", "OIDF Conformance Suite"),
        FAPI2_FINAL_OVERRIDES,
        browser=[FAPI2_FINAL_AUTHORIZE],
        base=RUSTID_FAPI2_FINAL,
        client2=fapi2_client("client2", "fapi2-conformance-client-2", "OIDF Conformance Suite 2"),
        resource={"resourceUrl": f"{RUSTID_FAPI2_FINAL}/fapi2/resource"},
        waitTimeoutSeconds=30,
    ),
    "fapi2-ms": plan(
        "rustid-fapi2-ms",
        "rustid FAPI 2.0 Message Signing (final)",
        fapi2_client(
            "client1", "fapi2-conformance-client", "OIDF Conformance Suite", "rustid-fapi2-ms"
        ),
        FAPI2_MS_OVERRIDES,
        browser=[FAPI2_MS_AUTHORIZE],
        base=RUSTID_FAPI2_MS,
        client2=fapi2_client(
            "client2", "fapi2-conformance-client-2", "OIDF Conformance Suite 2", "rustid-fapi2-ms"
        ),
        resource={"resourceUrl": f"{RUSTID_FAPI2_MS}/fapi2/resource"},
        waitTimeoutSeconds=30,
    ),
    "dynamic": plan(
        "rustid-dynamic",
        "rustid OIDC dynamic registration",
        {"client_name": "rustid conformance client"},
        {**DYNAMIC_ERRORS, **DYNAMIC_LOGIN_PAGE},
        browser=[DYNAMIC_AUTHORIZE],
        base=RUSTID_DYNAMIC,
        client2={"client_name": "rustid conformance client 2"},
    ),
    "3rdparty": plan(
        "rustid-3rdparty",
        "rustid OIDC 3rd party initiated login",
        {"client_name": "rustid conformance client"},
        {},
        browser=[DYNAMIC_AUTHORIZE],
        base=RUSTID_DYNAMIC,
        client2={"client_name": "rustid conformance client 2"},
    ),
    "fapi-ciba": plan(
        "rustid-fapi-ciba",
        "rustid FAPI-CIBA (poll)",
        ciba_client(1, "fapi-ciba-conformance-client"),
        {},
        browser=[],
        base=RUSTID_CIBA,
        client2=ciba_client(2, "fapi-ciba-conformance-client-2"),
        mtls=ciba_mtls(1),
        mtls2=ciba_mtls(2),
        resource={"resourceUrl": f"{RUSTID_CIBA}/fapi-ciba/resource"},
        automated_ciba_approval_url="http://127.0.0.1:5451/approve?token={auth_req_id}&action={action}",
    ),
}

for name, config in PLANS.items():
    path = HERE / "plans" / f"{name}.json"
    path.write_text(json.dumps(config, indent=2) + "\n")
    print(f"wrote {path.relative_to(HERE.parent)}")
