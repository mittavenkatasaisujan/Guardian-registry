"""Bank conformance run: a bank's whole integration, against a live registry.

    python scripts/bank_conformance.py http://127.0.0.1:8010 --admin dev-admin [--setup-env live.env]

Uses the Python client library (sdk/python). It registers a test bank, enrols a protected
person and their guardian, registers a webhook receiver on localhost, then checks:

  1. a small payment is allowed, and the outcome report is accepted (and a retry of it too);
  2. retrying a check with the same transaction id returns the same check;
  3. a large payment is held; the guardian approves; a SIGNED check.updated webhook arrives
     with may_execute = true; the bank completes it;
  4. a denied payment arrives by webhook with may_execute = false;
  5. a customer who isn't enrolled passes straight through;
  6. a reported fraud payee holds the payment;
  7. an outcome label (fraud / genuine) is accepted;
  8. a tampered webhook body fails verification.

Partner banks run the same script against the sandbox before going live. --setup-env writes
the test bank's key and the test people for other clients (the Java library's live test).
Needs a registry in development mode (OTP codes echoed). Never point it at production.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import queue
import sys
import threading
import time
import uuid

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sdk", "python"))

from guardian_registry_client import Client, parse_webhook, verify_webhook  # noqa: E402

R = 100


class Hooks:
    """A tiny webhook receiver: keeps raw bodies and signatures."""

    def __init__(self):
        self.q: queue.Queue = queue.Queue()
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                outer.q.put((body, self.headers.get("X-GR-Signature"), self.headers.get("X-GR-Event")))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.server = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://localhost:{self.server.server_address[1]}/hook"

    def wait_for(self, check_id: str, status: str, timeout: float = 30):
        deadline = time.time() + timeout
        seen = []
        while time.time() < deadline:
            try:
                body, sig, event = self.q.get(timeout=1)
            except queue.Empty:
                continue
            seen.append((body, sig))
            doc = json.loads(body)
            chk = doc.get("data", {}).get("check", {})
            if event == "check.updated" and chk.get("check_id") == check_id and chk.get("status") == status:
                return body, sig
        raise AssertionError(f"no check.updated webhook for {check_id} -> {status} within {timeout}s")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--admin", required=True, help="an operator token (development registry)")
    ap.add_argument("--setup-env", help="also write GR_LIVE_* settings here for other clients")
    a = ap.parse_args(argv)
    base = a.base.rstrip("/")
    h = httpx.Client(base_url=base, timeout=20)
    run = uuid.uuid4().hex[:6]
    ok_count = 0

    def must(r, code=200):
        if r.status_code != code:
            raise SystemExit(f"setup failed: {r.request.method} {r.request.url.path} -> {r.status_code} {r.text[:300]}")
        return r.json() if r.content else {}

    def passed(name):
        nonlocal ok_count
        ok_count += 1
        print(f"PASS {ok_count}. {name}")

    # ---------------------------------------------------------------- setup
    admin = {"X-Admin-Token": a.admin}
    ref = f"RBI-CONF-{run}"
    must(h.put("/v1/admin/register/bank", headers=admin, json={
        "source": "conformance run", "as_of": "2026-11-23", "entities": [{"regulator_ref": ref, "name": "Conformance Bank"}]}))
    bank = must(h.post("/v1/admin/participants", headers=admin,
                       json={"name": f"Conformance Bank {run}", "kind": "bank", "regulator_ref": ref}), 201)
    if bank["status"] != "active":
        raise SystemExit("this registry needs a second operator to approve banks; use a development registry")
    api_key = bank["api_key"]

    def person(mobile, name):
        code = must(h.post("/v1/auth/otp", json={"mobile": mobile}), 202)["dev_code"]
        return must(h.post("/v1/auth/verify", json={"mobile": mobile, "code": code, "display_name": name}))["token"]

    digits = str(uuid.uuid4().int)[:7]
    elder, carer = f"+91971{digits}", f"+91972{digits}"
    elder_tok, carer_tok = person(elder, "Conformance Elder"), person(carer, "Conformance Carer")
    E, C = {"Authorization": f"Bearer {elder_tok}"}, {"Authorization": f"Bearer {carer_tok}"}
    inv = must(h.post("/v1/me/guardians", headers=E, json={"mobile": carer}), 201)
    must(h.post(f"/v1/guardian/invitations/{inv['id']}/accept", headers=C))
    must(h.patch("/v1/me/rules", headers=E, json={"approval_threshold": 10_000 * R}))
    if a.setup_env:
        with open(a.setup_env, "w") as f:
            f.write(f"GR_LIVE_URL={base}\nGR_LIVE_API_KEY={api_key}\nGR_LIVE_MOBILE={elder}\n"
                    f"GR_LIVE_GUARDIAN_TOKEN={carer_tok}\n")

    gr = Client(base, api_key)
    hooks = Hooks()
    secret = gr.set_webhook(hooks.url)["webhook_secret"]

    # ---------------------------------------------------------------- scenarios
    r = gr.check(elder, f"small-{run}", 500 * R, "known@upi")
    assert r.may_execute and r.status == "allowed", r
    gr.report_outcome(r.check_id, True)
    gr.report_outcome(r.check_id, True)
    passed("small payment allowed; outcome reported (and the retry accepted)")

    again = gr.check(elder, f"small-{run}", 500 * R, "known@upi")
    assert again.check_id == r.check_id
    passed("same transaction id returns the same check")

    big = gr.check(elder, f"big-{run}", 20_000 * R, "known@upi")
    assert big.waiting and not big.may_execute and big.status == "pending_approval", big
    must(h.post(f"/v1/guardian/payments/{big.check_id}/approve", headers=C))
    body, sig = hooks.wait_for(big.check_id, "approved")
    event = parse_webhook(secret, body, sig)
    assert event["data"]["check"]["may_execute"] is True
    gr.report_outcome(big.check_id, True)
    passed("large payment held; guardian approved; signed webhook said execute; completed")

    deny = gr.check(elder, f"deny-{run}", 15_000 * R, "known@upi")
    must(h.post(f"/v1/guardian/payments/{deny.check_id}/deny", headers=C))
    body2, sig2 = hooks.wait_for(deny.check_id, "denied")
    assert parse_webhook(secret, body2, sig2)["data"]["check"]["may_execute"] is False
    passed("denied payment arrived by signed webhook with may_execute = false")

    ne = gr.check(f"+91973{digits}", f"ne-{run}", 100 * R, "x@upi")
    assert ne.may_execute and not ne.enrolled
    passed("customer not enrolled: passes through")

    gr.report_fraud_payee(f"mule-{run}@upi", "conformance: confirmed fraud case", f"CONF-{run}")
    held = gr.check(elder, f"mule-{run}", 100 * R, f"mule-{run}@upi")
    assert held.waiting and any("reported fraud" in x for x in held.reasons), held
    passed("reported fraud payee holds the payment")

    assert gr.label_fraud(deny.check_id, True, "conformance: customer confirmed a scam")["label"] == "fraud"
    passed("outcome label accepted")

    assert not verify_webhook(secret, body.replace(b"approved", b"APPROVED"), sig)
    passed("tampered webhook body fails verification")

    print(f"\nall {ok_count} conformance checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
