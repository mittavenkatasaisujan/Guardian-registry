"""End-to-end demo against a RUNNING server, over real HTTP.

    $env:GR_ADMIN_TOKEN = "demo-admin"; $env:GR_DB = "demo.db"
    .venv\\Scripts\\uvicorn guardian_registry.api:create_app --factory --port 8000
    .venv\\Scripts\\python scripts\\demo.py http://127.0.0.1:8000 demo-admin

Story: Amma (72) sets Ravi as her guardian. Two banks check every payment against
one set of rules. A scam call tries a large transfer and then tries to get the
protection switched off; both are stopped. A genuine payment goes through.
"""

import hashlib
import hmac
import json
import random
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx

HOOK_PORT = 8799
HOOK_SECRET = [""]
HOOK_EVENTS: list[dict] = []


class HookHandler(BaseHTTPRequestHandler):
    """Plays the bank's webhook endpoint: verifies the signature, records the event."""

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        expected = "sha256=" + hmac.new(HOOK_SECRET[0].encode(), body, hashlib.sha256).hexdigest()
        ok = hmac.compare_digest(expected, self.headers.get("X-GR-Signature", ""))
        HOOK_EVENTS.append({"signature_ok": ok, **json.loads(body)})
        self.send_response(200 if ok else 401)
        self.end_headers()

    def log_message(self, *a):
        pass


threading.Thread(target=HTTPServer(("127.0.0.1", HOOK_PORT), HookHandler).serve_forever, daemon=True).start()

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "demo-admin"
R = 100
run = random.randint(100000, 999999)  # fresh numbers each run so the demo can be re-run


def mobile(n):  # valid Indian mobile, unique per run
    return f"9{run:06d}{n:03d}"


c = httpx.Client(base_url=BASE, timeout=10)


def call(method, path, expect=200, **kw):
    r = c.request(method, path, **kw)
    if r.status_code != expect:
        raise SystemExit(f"FAIL {method} {path}: {r.status_code} {r.text}")
    return r.json()


def step(msg):
    print(f"\n== {msg}")


def bearer(t):
    return {"Authorization": f"Bearer {t}"}


step("health")
print(call("GET", "/healthz"))

step("operator onboards two banks")
sbi = {"X-Api-Key": call("POST", "/v1/admin/participants", 201, json={"name": f"Bank A {run}"},
                         headers={"X-Admin-Token": ADMIN})["api_key"]}
app = {"X-Api-Key": call("POST", "/v1/admin/participants", 201, json={"name": f"UPI App B {run}"},
                         headers={"X-Admin-Token": ADMIN})["api_key"]}
print("Bank A and UPI App B have API keys")

step("Bank A registers a webhook (a real local HTTP receiver that checks signatures)")
hook = call("PUT", "/v1/participant/webhook", headers=sbi, json={"url": f"http://127.0.0.1:{HOOK_PORT}/gr"})
HOOK_SECRET[0] = hook["webhook_secret"]
print("webhook secret issued:", hook["webhook_secret"][:8] + "...")

step("Amma and Ravi sign in with an SMS code (server runs with GR_OTP_DEV_ECHO=1)")


def sign_in(n, name):
    code = call("POST", "/v1/auth/otp", 202, json={"mobile": mobile(n)})["dev_code"]
    bad = c.post("/v1/auth/verify", json={"mobile": mobile(n), "code": "000000" if code != "000000" else "111111",
                                          "display_name": name})
    out = call("POST", "/v1/auth/verify", json={"mobile": mobile(n), "code": code, "display_name": name})
    print(f"{name}: wrong code -> {bad.status_code}, right code -> new_user={out['new_user']}")
    return out


amma, ravi = sign_in(1, "Amma"), sign_in(2, "Ravi")
A, G = bearer(amma["token"]), bearer(ravi["token"])
link = call("POST", "/v1/me/guardians", 201, json={"mobile": mobile(2)}, headers=A)
print("invite status:", link["status"])
print("accepted:", call("POST", f"/v1/guardian/invitations/{link['id']}/accept", headers=G)["status"])

step("Amma applies the 'senior_with_guardian' preset, then tightens limits (applies at every bank)")
out = call("POST", "/v1/me/rules/preset/senior_with_guardian", headers=A)
print("preset applied now:", list(out["applied"]))
out = call("PATCH", "/v1/me/rules", headers=A, json={"per_txn_limit": 50_000 * R, "daily_limit": 60_000 * R})
print("tightened now:", list(out["applied"]))

step("Bank A: ₹800 to the vegetable seller -> allowed")
r = call("POST", "/v1/checks", headers=sbi, json={"mobile": mobile(1), "participant_txn_id": "veg-1",
                                                  "amount": 800 * R, "payee": "veggies@upi"})
print(r["outcome"], "| may_execute:", r["may_execute"])
call("POST", f"/v1/checks/{r['check_id']}/outcome", headers=sbi, json={"completed": True})

step("SCAM CALL: UPI App B, ₹45,000 to 'refund-desk@upi' -> needs Ravi's approval")
scam = call("POST", "/v1/checks", headers=app, json={"mobile": mobile(1), "participant_txn_id": "scam-1",
                                                     "amount": 45_000 * R, "payee": "refund-desk@upi"})
print(scam["outcome"], "|", "; ".join(scam["reasons"]))
inbox = call("GET", "/v1/guardian/inbox", headers=G)
print("Ravi's inbox:", [(h["payee"], h["amount"] // R, h["status"]) for h in inbox["held_payments"]])
alert = call("GET", "/v1/me/notifications", headers=G)[0]
print(f"Ravi's alert (also sent by SMS): {alert['title']} - {alert['body']}")
print("Ravi denies:", call("POST", f"/v1/guardian/payments/{scam['check_id']}/deny", headers=G)["status"])
print("bank re-checks, may_execute:", call("GET", f"/v1/checks/{scam['check_id']}", headers=app)["may_execute"])

step("Scammer: 'remove your limits' -> held 24h, Ravi vetoes")
held = call("PATCH", "/v1/me/rules", headers=A, json={"approval_threshold": None, "per_txn_limit": None})
chg = held["held"]["change"]
print("held until:", chg["effective_at"])
print("Ravi vetoes:", call("POST", f"/v1/guardian/changes/{chg['id']}/veto", headers=G)["status"])
print("rules unchanged:", call("GET", "/v1/me/rules", headers=A)["approval_threshold"] // R)

step("Scammer: 'remove Ravi as guardian' -> also held; Ravi can't veto his own removal")
rm = call("DELETE", f"/v1/me/guardians/{link['id']}", headers=A)
print("applied immediately:", rm["applied"])
r = c.post(f"/v1/guardian/changes/{rm['change']['id']}/veto", headers=G)
print("Ravi self-veto ->", r.status_code, r.json()["detail"])

step("Ravi hits the kill switch while he drives over")
call("POST", f"/v1/guardian/wards/{amma['user_id']}/kill-switch/on", headers=G)
for bank, name in ((sbi, "Bank A"), (app, "UPI App B")):
    r = call("POST", "/v1/checks", headers=bank, json={"mobile": mobile(1), "participant_txn_id": f"lock-{name}",
                                                       "amount": 100 * R, "payee": "veggies@upi"})
    print(f"{name}: ₹100 ->", r["outcome"])

step("Ravi switches payments back on; genuine ₹15,000 hospital bill, Ravi approves")
call("POST", f"/v1/guardian/wards/{amma['user_id']}/kill-switch/off", headers=G)
call("POST", f"/v1/guardian/wards/{amma['user_id']}/trusted-payees", 201, headers=G, json={"payee": "cityhospital@upi"})
bill = call("POST", "/v1/checks", headers=sbi, json={"mobile": mobile(1), "participant_txn_id": "hosp-1",
                                                     "amount": 15_000 * R, "payee": "cityhospital@upi"})
print(bill["outcome"])
call("POST", f"/v1/guardian/payments/{bill['check_id']}/approve", headers=G)
bill = call("GET", f"/v1/checks/{bill['check_id']}", headers=sbi)
print("after approval:", bill["status"], "| may_execute:", bill["may_execute"])
call("POST", f"/v1/checks/{bill['check_id']}/outcome", headers=sbi, json={"completed": True})

step("Bank A was told by webhook instead of polling")
for _ in range(50):  # the server's background worker delivers within a few seconds
    if any(e["data"]["check"]["check_id"] == bill["check_id"] for e in HOOK_EVENTS):
        break
    time.sleep(0.2)
else:
    call("POST", "/v1/admin/sweep", headers={"X-Admin-Token": ADMIN})
    time.sleep(0.5)
ev = next(e for e in HOOK_EVENTS if e["data"]["check"]["check_id"] == bill["check_id"])
print(f"webhook {ev['event']}: status={ev['data']['check']['status']} may_execute={ev['data']['check']['may_execute']} "
      f"signature_ok={ev['signature_ok']}")
assert ev["signature_ok"]

step("Daily limit is shared across banks (₹60,000/day)")
spent = 800 + 15_000
i = 0
while True:
    i += 1
    r = call("POST", "/v1/checks", headers=app if i % 2 else sbi,
             json={"mobile": mobile(1), "participant_txn_id": f"day-{i}", "amount": 9_000 * R, "payee": "veggies@upi"})
    if r["outcome"] != "allow":
        print(f"payment {i} (₹9,000) after ₹{spent:,} spent ->", r["outcome"], "|", r["reasons"][0])
        break
    spent += 9_000

step("Bank A rotates its API key; the old key keeps working during the grace period")
new_key = call("POST", "/v1/participant/rotate-key", headers=sbi)
print("old key valid until:", new_key["previous_key_valid_until"])
print("old key still works:", c.get("/healthz").status_code == 200 and
      c.post("/v1/checks", headers=sbi, json={"mobile": mobile(1), "participant_txn_id": "rot-old",
                                               "amount": 100, "payee": "veggies@upi"}).status_code == 200)
sbi = {"X-Api-Key": new_key["api_key"]}

step("Amma signs out of every device")
c.post("/v1/auth/logout", json={"everywhere": True}, headers=A)
print("old token now ->", c.get("/v1/me", headers=A).status_code)

step("Audit trail (Ravi reads Amma's, as her guardian)")
trail = call("GET", f"/v1/guardian/wards/{amma['user_id']}/audit", headers=G)
print(len(trail), "entries for Amma, e.g.:", [e["action"] for e in trail[-6:]])
print("chain verification:", call("GET", "/v1/admin/audit/verify", headers={"X-Admin-Token": ADMIN}))

print("\nDEMO OK")
