#!/usr/bin/env python3
"""Runs the OpenID Foundation relying-party plan against rustid's upstream
federation. The suite acts as the upstream provider; for each test module
this starts a sign-in at rustid (conformance/rp/rustid.toml) with
acr_values=idp:oidf, follows the redirects with one cookie jar, and lets the
suite judge what rustid did. Negative modules expect rustid to refuse: it
stops at its error page and never calls userinfo.

Exits non-zero when a module's result isn't PASSED, unless
conformance/expected/rp-failures.json lists it with that result.
"""

import asyncio
import json
import os
import sys
import urllib.parse

import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SUITE = os.environ.get("SUITE_DIR", os.path.join(ROOT, "target", "conformance", "suite"))
sys.path.insert(0, os.path.join(SUITE, "scripts"))
from conformance import Conformance  # noqa: E402

SERVER = os.environ.get("CONFORMANCE_SERVER", "https://localhost:8443/")
RUSTID = "https://localhost:9448"
PLAN = "oidcc-client-basic-certification-test-plan"
VARIANT = {
    "client_registration": "static_client",
    "request_type": "plain_http_request",
}
CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
AUTHORIZE = (
    f"{RUSTID}/connect/authorize?client_id=rp-driver"
    "&redirect_uri=https%3A%2F%2Fclient.test%2Fcallback&response_type=code"
    f"&scope=openid%20profile&state=s&code_challenge={CHALLENGE}"
    "&code_challenge_method=S256&acr_values=idp%3Aoidf"
)


async def sign_in() -> str:
    """Starts a sign-in at rustid and follows it; what rustid ended with."""
    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=30) as browser:
        url = AUTHORIZE
        for _ in range(20):
            response = await browser.get(url)
            if response.status_code not in (301, 302, 303, 307, 308):
                return f"stopped at {url.split('?')[0]} with {response.status_code}"
            location = response.headers["location"]
            if location.startswith("https://client.test/"):
                query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
                return "code for the client" if "code" in query else f"client got {query}"
            url = urllib.parse.urljoin(url, location)
        return "too many redirects"


async def main() -> int:
    conformance = Conformance(SERVER, None, False)
    with open(os.path.join(ROOT, "conformance", "rp", "plan.json")) as f:
        configuration = f.read()
    expected_file = os.path.join(ROOT, "conformance", "expected", "rp-failures.json")
    expected = json.load(open(expected_file)) if os.path.exists(expected_file) else {}
    plan = await conformance.create_test_plan(PLAN, configuration, VARIANT)
    print(f"plan {plan['id']}: {SERVER}plan-detail.html?plan={plan['id']}")
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
        outcome = await sign_in() if state == "WAITING" else "not started"
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
    await conformance.close_client()
    return status


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
