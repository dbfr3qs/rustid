#!/usr/bin/env python3
"""The FAPI-CIBA conformance run's stand-in for a user's authentication
device, on http://127.0.0.1:5451 (conformance only, never the demo):

- POST /ciba/user: rustid's CIBA user hook. The login hint "alice" is alice;
  anything else is no one.
- POST /ciba/notify: rustid's CIBA notification hook. It remembers the
  pending request's internal id.
- POST /approve?token=<auth_req_id>&action=allow|deny: the suite's
  automated_ciba_approval_url. It signs alice in at rustid's reference UI
  (once), then completes the pending request through the interaction API,
  approving or refusing.

Hook calls carry a JWT the server signs; this test double doesn't check it.
"""

import http.cookiejar
import json
import ssl
import sys
import threading
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RUSTID = "https://localhost:9445"
API_KEY = "fapi-ciba-approver-key"
USER = ("alice", "alice")
# alice's subject id in conformance/users.json.
SUBJECT = "1"
PORT = 5451

pending = {"internal_id": None, "scopes": []}
lock = threading.Lock()
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


jar = http.cookiejar.CookieJar()
browser = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(jar),
    urllib.request.HTTPSHandler(context=TLS),
    NoRedirect,
)
signed_in = {"done": False}


def fetch(url, data=None, headers=None, method=None):
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        response = browser.open(request)
        return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def location(headers, base):
    return urllib.parse.urljoin(base, headers.get("Location") or headers.get("location"))


def sign_in():
    """alice through the reference UI's login form, as a browser would."""
    query = urllib.parse.urlencode({
        "client_id": "fapi-ciba-approver",
        "response_type": "code",
        "scope": "openid",
        "redirect_uri": f"{RUSTID}/approver/signed-in",
        "state": "s",
        "nonce": "n",
    })
    status, headers, _ = fetch(f"{RUSTID}/connect/authorize?{query}")
    login = location(headers, RUSTID)
    return_url = urllib.parse.parse_qs(urllib.parse.urlparse(login).query)["ReturnUrl"][0]
    fetch(login)  # the login page (and the interaction binding cookie)
    form = urllib.parse.urlencode({
        "returnUrl": return_url, "username": USER[0], "password": USER[1], "button": "login",
    }).encode()
    status, headers, body = fetch(
        login, data=form, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Origin": RUSTID},
    )
    url = location(headers, login)
    for _ in range(5):  # the continuation sets the session cookie
        if "/approver/signed-in" in url:
            break
        status, headers, _ = fetch(url)
        if status not in (301, 302, 303):
            break
        url = location(headers, url)
    signed_in["done"] = True


def complete(action):
    with lock:
        if not signed_in["done"]:
            sign_in()
        internal_id = pending["internal_id"]
        scopes = list(pending["scopes"])
    if internal_id is None:
        raise RuntimeError("no pending CIBA request was notified")
    # Approving consents to every requested scope; refusing denies.
    body = {"id": internal_id, "scopes": scopes} if action == "allow" else {
        "id": internal_id, "error": "access_denied"}
    status, _, answer = fetch(
        f"{RUSTID}/interaction/ciba", data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"},
    )
    if status != 200:
        raise RuntimeError(f"interaction/ciba answered {status}: {answer[:300]!r}")


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, value):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}") if length else {}
        if url.path == "/ciba/user":
            if body.get("login_hint") == USER[0]:
                return self.reply(200, {"version": 1, "subject": {"sub": SUBJECT}})
            return self.reply(200, {"version": 1})
        if url.path == "/ciba/notify":
            with lock:
                pending["internal_id"] = body.get("internal_id")
                pending["scopes"] = body.get("scopes") or []
            return self.reply(200, {"version": 1})
        if url.path == "/approve":
            action = urllib.parse.parse_qs(url.query).get("action", ["allow"])[0]
            try:
                complete(action)
            except Exception as e:  # reported to the suite, which logs it
                return self.reply(500, {"error": str(e)})
            return self.reply(200, {"result": action})
        self.reply(404, {"error": "not_found"})

    def log_message(self, fmt, *args):
        sys.stderr.write("approver: " + fmt % args + "\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
