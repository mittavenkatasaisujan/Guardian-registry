"""End-to-end demo against a RUNNING server, over real HTTP.

    $env:GR_ADMIN_TOKEN = "demo-admin"; $env:GR_DB = "demo.db"
    .venv\\Scripts\\uvicorn guardian_registry.api:create_app --factory --port 8000
    .venv\\Scripts\\python scripts\\demo.py http://127.0.0.1:8000 demo-admin

Story: Amma (72) sets Ravi as her guardian. Two banks check every payment against
one set of rules. A scam call tries a large transfer and then tries to get the
protection switched off; both are stopped. A genuine payment goes through.
"""

import random
import sys

import httpx

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

step("Amma and Ravi enrol; Amma invites Ravi; Ravi consents")
amma = call("POST", "/v1/users", 201, json={"mobile": mobile(1), "display_name": "Amma"})
ravi = call("POST", "/v1/users", 201, json={"mobile": mobile(2), "display_name": "Ravi"})
A, G = bearer(amma["token"]), bearer(ravi["token"])
link = call("POST", "/v1/me/guardians", 201, json={"mobile": mobile(2)}, headers=A)
print("invite status:", link["status"])
print("accepted:", call("POST", f"/v1/guardian/invitations/{link['id']}/accept", headers=G)["status"])

step("Amma sets her rules once (applies at every bank)")
out = call("PATCH", "/v1/me/rules", headers=A, json={
    "per_txn_limit": 50_000 * R, "daily_limit": 60_000 * R,
    "approval_threshold": 10_000 * R, "new_payee_delay_threshold": 5_000 * R})
print("applied now:", list(out["applied"]))

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

step("Audit trail")
trail = call("GET", "/v1/me/audit", headers=A)
print(len(trail), "entries for Amma, e.g.:", [e["action"] for e in trail[-6:]])
print("chain verification:", call("GET", "/v1/admin/audit/verify", headers={"X-Admin-Token": ADMIN}))

print("\nDEMO OK")
