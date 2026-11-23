"""End-to-end demo against a RUNNING server, over real HTTP.

    $env:GR_OPERATORS = "alice:demo-alice-token,bob:demo-bob-token"; $env:GR_DB = "demo.db"
    $env:GR_OTP_DEV_ECHO = "1"
    .venv\\Scripts\\uvicorn guardian_registry.api:create_app --factory --port 8000
    .venv\\Scripts\\python scripts\\demo.py http://127.0.0.1:8000 demo-alice-token demo-bob-token

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
ADMIN = sys.argv[2] if len(sys.argv) > 2 else "demo-alice-token"    # operator 1
ADMIN2 = sys.argv[3] if len(sys.argv) > 3 else "demo-bob-token"     # operator 2 (four-eyes)
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

step("operator Alice registers a bank, a UPI app and a mobile operator; operator Bob must approve (four-eyes)")
op1, op2 = {"X-Admin-Token": ADMIN}, {"X-Admin-Token": ADMIN2}
for kind, ref, name in (("bank", f"RBI-BANK-{run}", "Bank A"), ("tpap", f"NPCI-TPAP-{run}", "UPI App B"),
                        ("telecom", f"DOT-UL-{run}", "Telco C")):
    call("PUT", f"/v1/admin/register/{kind}", headers=op1, json={
        "source": "demo copy of the regulator's published list", "as_of": "2026-11-01",
        "entities": [{"regulator_ref": ref, "name": name}]})
print("official registers loaded:", [f"{r['kind']}={r['entities']}" for r in call("GET", "/v1/admin/register", headers=op1)])
r = c.post("/v1/admin/participants", headers=op1, json={"name": f"Totally Real Bank {run}", "kind": "bank",
                                                        "regulator_ref": "RBI-MADE-UP"})
print("a 'bank' with a made-up licence number ->", r.status_code, r.json()["detail"][:60] + "...")
keys = {}
for label, kind, ref in (("Bank A", "bank", f"RBI-BANK-{run}"), ("UPI App B", "tpap", f"NPCI-TPAP-{run}"),
                         ("Telco C", "telecom", f"DOT-UL-{run}")):
    p = call("POST", "/v1/admin/participants", 201, headers=op1,
             json={"name": f"{label} {run}", "kind": kind, "regulator_ref": ref})
    keys[label] = ({"X-Api-Key": p["api_key"]}, p["participant_id"])
    print(f"{label}: {p['kind']} status={p['status']} capabilities={p['capabilities']}")
sbi, app, telco = keys["Bank A"][0], keys["UPI App B"][0], keys["Telco C"][0]
r = c.post("/v1/checks", headers=sbi, json={"mobile": mobile(1), "participant_txn_id": "too-early",
                                            "amount": 100, "payee": "x@upi"})
print("Bank A calls checks before approval ->", r.status_code, r.json()["detail"])
r = c.post(f"/v1/admin/participants/{keys['Bank A'][1]}/approve", headers=op1)
print("Alice approves her own request ->", r.status_code, r.json()["detail"])
for label in keys:
    print(f"Bob approves {label} ->",
          call("POST", f"/v1/admin/participants/{keys[label][1]}/approve", headers=op2)["status"])

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

step("Bank A vouches for Amma and Ravi (KYC); each approves in their app")
for who, tok, n, dob, ref in ((amma, A, 1, "1952-03-10", "CIF-1001"), (ravi, G, 2, "1984-08-15", "CIF-2002")):
    att = call("POST", "/v1/kyc/attestations", 201, headers=sbi, json={
        "mobile": mobile(n), "kyc_level": "full", "customer_ref": ref, "verified_on": "2025-06-01",
        "date_of_birth": dob})
    note = call("GET", "/v1/me/notifications", headers=tok)[0]
    print(f"alert: {note['title']} - {note['body'][:80]}...")
    call("POST", f"/v1/me/identity/attestations/{att['attestation_id']}/approve", headers=tok)
r = c.post("/v1/kyc/attestations", headers=app, json={
    "mobile": mobile(1), "kyc_level": "full", "customer_ref": "X", "verified_on": "2025-06-01"})
print("UPI App B tries to vouch for Amma's identity ->", r.status_code, r.json()["detail"])
ident = call("GET", "/v1/me/identity", headers=A)
print(f"Amma: identity={ident['level']} senior={ident['senior']} (banks never see the date of birth)")
print("Ravi as guardian:", call("GET", "/v1/me/guardians", headers=A)[0]["guardian_identity_level"])
print("Amma requires bank-verified approvers:",
      call("PATCH", "/v1/me/rules", headers=A, json={"require_verified_guardian": True})["applied"])

step("Bank A: ₹800 to the vegetable seller -> allowed")
r = call("POST", "/v1/checks", headers=sbi, json={"mobile": mobile(1), "participant_txn_id": "veg-1",
                                                  "amount": 800 * R, "payee": "veggies@upi"})
print(r["outcome"], "| may_execute:", r["may_execute"], "| customer:", r["customer"])
assert r["customer"] == {"identity_level": "bank_verified", "senior": True}
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
def check_events():
    return [e for e in HOOK_EVENTS if e["event"] == "check.updated"]


for _ in range(50):  # the server's background worker delivers within a few seconds
    if any(e["data"]["check"]["check_id"] == bill["check_id"] for e in check_events()):
        break
    time.sleep(0.2)
else:
    call("POST", "/v1/admin/sweep", headers={"X-Admin-Token": ADMIN})
    time.sleep(0.5)
ev = next(e for e in check_events() if e["data"]["check"]["check_id"] == bill["check_id"])
print(f"webhook {ev['event']}: status={ev['data']['check']['status']} may_execute={ev['data']['check']['may_execute']} "
      f"signature_ok={ev['signature_ok']}")
assert ev["signature_ok"]
kyc_events = [e for e in HOOK_EVENTS if e["event"] == "kyc.updated"]
print(f"Bank A also got {len(kyc_events)} kyc.updated events (consent decisions): "
      f"{[e['data']['attestation']['status'] for e in kyc_events]}")
assert len(kyc_events) == 2 and all(e["signature_ok"] for e in kyc_events)

step("SIM SWAP: a thief gets Ravi's number moved to their SIM and signs in as Ravi")
print("Bank A reports the SIM change:",
      call("POST", "/v1/signals/sim-change", headers=sbi, json={"mobile": mobile(2)})["window_open"])
pending = call("POST", "/v1/checks", headers=app, json={"mobile": mobile(1), "participant_txn_id": "swap-1",
                                                        "amount": 30_000 * R, "payee": "mule@upi"})
print("₹30,000 to mule@upi ->", pending["outcome"])
wait = 31  # the thief has to wait out the OTP resend cooldown from Ravi's earlier sign-in
print(f"(waiting {wait}s for the OTP resend cooldown...)")
time.sleep(wait)
code = call("POST", "/v1/auth/otp", 202, json={"mobile": mobile(2)})["dev_code"]  # the code reaches the thief's SIM
thief = call("POST", "/v1/auth/verify", json={"mobile": mobile(2), "code": code, "device_id": "thief-phone"})
print("thief signed in, restricted:", thief["restricted"], "|", thief["restriction_reasons"][0][:60] + "...")
T = bearer(thief["token"])
r = c.post(f"/v1/guardian/payments/{pending['check_id']}/approve", headers=T)
print("thief tries to approve ->", r.status_code, r.json()["error"])
r = c.post("/v1/me/security/confirm-sim-change", headers=T)
print("thief tries to 'confirm' the SIM change ->", r.status_code)
print("real Ravi (old phone) denies it:", call("POST", f"/v1/guardian/payments/{pending['check_id']}/deny", headers=G)["status"])
print("risk window still open while Ravi sorts it out with his operator:",
      call("GET", "/v1/me/security", headers=G)["sim_swap_window_open"])

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

step("NUMBER RECYCLED: Ravi's old number is disconnected, then given to a stranger")
from datetime import datetime, timezone  # noqa: E402

now = datetime.now(timezone.utc).isoformat()
out = call("POST", "/v1/signals/operator-events", headers=telco, json={"events": [
    {"event_id": f"dc-{run}", "type": "disconnected", "mobile": mobile(2), "occurred_at": now}]})
print("Telco C reports the disconnection ->", out["counts"])
again = call("POST", "/v1/signals/operator-events", headers=telco, json={"events": [
    {"event_id": f"dc-{run}", "type": "disconnected", "mobile": mobile(2), "occurred_at": now}]})
print("resent by mistake ->", again["results"][0]["result"])
print("Ravi's account:", call("GET", "/v1/me", headers=G)["number_status"],
      "| Amma is told:", call("GET", "/v1/me/notifications", headers=A)[0]["title"])
for _ in range(25):  # wait out the OTP resend cooldown from the thief's sign-in above
    r = c.post("/v1/auth/otp", json={"mobile": mobile(2)})
    if r.status_code == 202:
        break
    time.sleep(2)
else:
    raise SystemExit(f"FAIL OTP for the stranger: {r.status_code} {r.text}")
stranger = call("POST", "/v1/auth/verify", json={"mobile": mobile(2), "code": r.json()["dev_code"],
                                                 "display_name": "New owner"})
S = bearer(stranger["token"])
print("stranger signs in with the old number -> new_user:", stranger["new_user"],
      "| people they guard:", call("GET", "/v1/guardian/wards", headers=S))
print("Ravi, on his signed-in phone, still guards:",
      [w["principal_name"] for w in call("GET", "/v1/guardian/wards", headers=G) if w["status"] == "active"])

step("Audit trail (Ravi reads Amma's, as her guardian)")
trail = call("GET", f"/v1/guardian/wards/{amma['user_id']}/audit", headers=G)
print(len(trail), "entries for Amma, e.g.:", [e["action"] for e in trail[-6:]])

step("RECOVERY: Ravi also loses his phone, so nothing is signed in; he recovers on a new number")
c.post("/v1/auth/logout", json={"everywhere": True}, headers=G)
print("Ravi's old phone ->", c.get("/v1/me", headers=G).status_code)
new_code = call("POST", "/v1/auth/otp", 202, json={"mobile": mobile(5)})["dev_code"]
rec = call("POST", "/v1/recovery/start", 202, json={"old_mobile": mobile(2), "new_mobile": mobile(5),
                                                    "code": new_code})
code2 = call("POST", "/v1/auth/otp", 202, json={"mobile": mobile(6)})["dev_code"]
fake = call("POST", "/v1/recovery/start", 202, json={"old_mobile": mobile(9), "new_mobile": mobile(6),
                                                     "code": code2})
print("recovery started -> status", rec["status"],
      "| same answer for a number that matches nothing:", sorted(rec) == sorted(fake))
ask = call("GET", "/v1/guardian/recoveries", headers=A)[0]
print(f"Amma is asked to vouch for {ask['person_name']} moving to {ask['new_number']}")
r = c.post(f"/v1/guardian/recoveries/{ask['recovery_id']}/approve", headers=A)
print("Amma tries to vouch at once ->", r.status_code, r.json()["detail"][:75] + "...")
print("(after the hour she can vouch; then 24 h for anyone to stop it, and 72 h of restricted sign-ins after)")
print("Ravi checks progress:", call("POST", "/v1/recovery/status", json={"recovery_token": rec["recovery_token"]})["status"])

print("\nchain verification:", call("GET", "/v1/admin/audit/verify", headers={"X-Admin-Token": ADMIN}))

step("Amma signs out of every device")
c.post("/v1/auth/logout", json={"everywhere": True}, headers=A)
print("old token now ->", c.get("/v1/me", headers=A).status_code)

print("\nDEMO OK")
