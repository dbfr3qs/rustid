#!/usr/bin/env python3
"""Runs the OpenID Foundation relying-party plans against rustid's upstream
federation. The suite acts as the upstream provider; for each test module
this starts a sign-in at rustid (conformance/rp/rustid.toml) with
acr_values=idp:oidf, follows the redirects with one cookie jar, and lets the
suite judge what rustid did. Negative modules expect rustid to refuse: it
stops at its error page and never calls userinfo.

The logout plans then sign out at rustid, which signs out at the suite too.
The suite posts a logout token to rustid's back-channel logout endpoint
(broken on purpose in the negative modules, which expect a 400), or renders
a page that frames rustid's front-channel logout endpoint: this loads the
frame and reports it loaded, as the page's script would.

Exits non-zero when a module's result isn't PASSED, unless
conformance/expected/rp-failures.json lists it with that result.
"""

import asyncio
import json
import os
import re
import sys
import urllib.parse

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SUITE = os.environ.get("SUITE_DIR", os.path.join(ROOT, "target", "conformance", "suite"))
sys.path.insert(0, os.path.join(SUITE, "scripts"))
from conformance import Conformance  # noqa: E402

SERVER = os.environ.get("CONFORMANCE_SERVER", "https://localhost:8443/")
RUSTID = "https://localhost:9448"
# Each plan, the provider (conformance/rp/identity-providers.json) rustid
# signs in through, and the logout URIs its client registers. Each plan has
# its own suite alias and provider, since rustid keeps a provider's
# discovery document and each plan's differs.
PLANS = [
    ("oidcc-client-basic-certification-test-plan", "oidf", None),
    ("oidcc-client-back-channel-logout-rp-basic", "oidf-bcl", ["backchannel"]),
    ("oidcc-client-front-channel-logout-rp-basic", "oidf-fcl", ["frontchannel"]),
    ("oidcc-client-rp-initiated-logout-rp-basic", "oidf-rpi", ["backchannel"]),
]
VARIANT = {
    "client_registration": "static_client",
    "request_type": "plain_http_request",
}
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
AUTHORIZE = (
    f"{RUSTID}/connect/authorize?client_id=rp-driver"
    "&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code"
    f"&scope=openid%20profile&state=s&code_challenge={CHALLENGE}"
    "&code_challenge_method=S256&acr_values=idp%3A"
)


REDIRECTS = (301, 302, 303, 307, 308)


def script_value(page: str, name: str) -> str | None:
    """A quoted value the suite's front-channel page script assigns."""
    match = re.search(re.escape(name) + r"\s*=\s*'([^']*)'", page)
    return match.group(1).replace("\\/", "/") if match else None


async def sign_in(browser: httpx.AsyncClient, scheme: str) -> str:
    """Starts a sign-in at rustid and follows it; what rustid ended with."""
    url = AUTHORIZE + scheme
    for _ in range(20):
        response = await browser.get(url)
        if response.status_code not in REDIRECTS:
            return f"stopped at {url.split('?')[0]} with {response.status_code}"
        location = response.headers["location"]
        if location.startswith("https://client.test/"):
            query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
            return "code for the client" if "code" in query else f"client got {query}"
        url = urllib.parse.urljoin(url, location)
    return "too many redirects"


async def sign_out(browser: httpx.AsyncClient) -> str:
    """Signs out at rustid and follows it through the suite's end session
    endpoint and back; where it ended."""
    url = f"{RUSTID}/account/logout"
    framed = ""
    for _ in range(20):
        response = await browser.get(url)
        if response.status_code in REDIRECTS:
            url = urllib.parse.urljoin(url, response.headers["location"])
            continue
        frame = script_value(response.text, "iframe.src")
        if response.status_code == 200 and frame:
            framed = f" (framed {frame.split('?')[0]}: {(await browser.get(frame)).status_code})"
            loaded = script_value(response.text, "let url")
            if loaded:
                await browser.get(loaded + ("&" if "?" in loaded else "?") + "loaded=true")
            url = script_value(response.text, "window.location.href") or url
            if url != "OPINIT":
                continue
        return f"signed out at {url.split('?')[0]} with {response.status_code}{framed}"
    return "too many redirects"


async def run_plan(conformance, name: str, scheme: str, logout, expected: dict) -> int:
    with open(os.path.join(ROOT, "conformance", "rp", "plan.json")) as f:
        configuration = json.load(f)
    federation = f"{RUSTID}/federation/{scheme}"
    configuration["alias"] = "rustid-rp" + scheme.removeprefix("oidf")
    configuration["client"]["redirect_uri"] = f"{federation}/callback"
    if logout:
        configuration["client"]["post_logout_redirect_uri"] = f"{federation}/signout-callback"
        for channel in logout:
            configuration["client"][f"{channel}_logout_uri"] = f"{federation}/{channel}-logout"
    variant = dict(VARIANT, client_auth_type="client_secret_basic") if logout else VARIANT
    plan = await conformance.create_test_plan(name, json.dumps(configuration), variant)
    print(f"plan {name} {plan['id']}: {SERVER}plan-detail.html?plan={plan['id']}")
    status = 0
    for entry in plan["modules"]:
        module = entry["testModule"]
        info = await conformance.create_test_from_plan_with_variant(
            plan["id"], module, entry.get("variant")
        )
        module_id = info["id"]
        state = await conformance.wait_for_state(module_id, ["CONFIGURED", "WAITING", "FINISHED"])
        if state == "CONFIGURED":
            state = await conformance.wait_for_state(module_id, ["WAITING", "FINISHED"])
        outcome = "not started"
        if state == "WAITING":
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=30) as browser:
                outcome = await sign_in(browser, scheme)
                if logout and outcome == "code for the client":
                    outcome += "; " + await sign_out(browser)
        try:
            await conformance.wait_for_state(module_id, ["FINISHED", "INTERRUPTED"], timeout=60)
            result = (await conformance.get_module_info(module_id)).get("result")
        except Exception:
            # A positive module waits for a userinfo call that never comes
            # when rustid refused the sign-in.
            result = "DID_NOT_FINISH"
        allowed = expected.get(module, "PASSED")
        ok = result == "PASSED" or result == allowed
        print(f"{'ok  ' if ok else 'FAIL'} {module}: {result} (rustid: {outcome})", flush=True)
        if not ok:
            status = 1
    os.makedirs(os.path.join(ROOT, "target", "conformance", "results"), exist_ok=True)
    await conformance.exporthtml(plan["id"], os.path.join(ROOT, "target", "conformance", "results"))
    return status


async def main() -> int:
    conformance = Conformance(SERVER, None, False)
    expected_file = os.path.join(ROOT, "conformance", "expected", "rp-failures.json")
    expected = json.load(open(expected_file)) if os.path.exists(expected_file) else {}
    status = 0
    only = sys.argv[1:]
    for name, scheme, logout in PLANS:
        if only and name not in only:
            continue
        status |= await run_plan(conformance, name, scheme, logout, expected)
    await conformance.close_client()
    return status


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
