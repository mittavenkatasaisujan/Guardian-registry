"""Smoke-test a running deployment through its real front door (nginx, TLS, mutual TLS).

    python scripts/smoke_deploy.py https://localhost:8443

Uses deploy/secrets and deploy/certs from scripts/deploy_init.py --dev. Checks: TLS with the
trial CA, readiness, four-eyes onboarding, that a bank's API key alone is refused once its
certificate is pinned and accepted with the real TLS client certificate, that a client
can't forge the certificate header, a person's sign-in and a payment check, the shared
audit chain, and that both API nodes answered.
"""

from __future__ import annotations

import ssl
import sys
import time
import uuid
from pathlib import Path

from urllib.parse import quote

import httpx

DEPLOY = Path(__file__).resolve().parent.parent / "deploy"


def main(base: str) -> int:
    certs, sec = DEPLOY / "certs", DEPLOY / "secrets"
    ops = dict(x.split(":", 1) for x in (sec / "operators").read_text().strip().split(","))
    alice, bob = {"X-Admin-Token": ops["alice"]}, {"X-Admin-Token": ops["bob"]}
    ca = str(certs / "ca.pem")
    trust = ssl.create_default_context(cafile=ca)
    plain = httpx.Client(base_url=base, verify=trust, timeout=20)
    with_cert = ssl.create_default_context(cafile=ca)  # the bank's side: presents its client certificate
    with_cert.load_cert_chain(str(certs / "bank.pem"), str(certs / "bank-key.pem"))
    bank_tls = httpx.Client(base_url=base, verify=with_cert, timeout=20)

    def ok(r, code=200):
        if r.status_code != code:
            raise SystemExit(f"FAIL {r.request.method} {r.request.url.path}: {r.status_code} {r.text[:300]}")
        return r.json() if r.content else {}

    for _ in range(60):
        try:
            if plain.get("/readyz").status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(2)
    print("ready:", ok(plain.get("/readyz")))
    run = uuid.uuid4().hex[:6]
    ref = f"RBI-SMOKE-{run}"
    ok(plain.put("/v1/admin/register/bank", headers=alice, json={
        "source": "smoke test", "as_of": "2026-11-23", "entities": [{"regulator_ref": ref, "name": "Smoke Bank"}]}))
    p = ok(plain.post("/v1/admin/participants", headers=alice, json={"name": f"Smoke Bank {run}", "kind": "bank",
                                                                      "regulator_ref": ref}), 201)
    pid, key = p["participant_id"], {"X-Api-Key": p["api_key"]}
    own = plain.post(f"/v1/admin/participants/{pid}/approve", headers=alice)
    assert own.status_code == 403, f"four-eyes: Alice approving her own request gave {own.status_code}"
    ok(plain.post(f"/v1/admin/participants/{pid}/approve", headers=bob))
    pin = ok(plain.post(f"/v1/admin/participants/{pid}/certificates", headers=alice,
                        json={"certificate": (certs / "bank.pem").read_text()}), 201)
    ok(plain.post(f"/v1/admin/participants/{pid}/certificates/{pin['fingerprint']}/approve", headers=bob))
    print("bank onboarded and its certificate pinned (four-eyes)")

    r = plain.get("/v1/participant/me", headers=key)
    assert r.status_code in (401, 403), f"API key alone must be refused, got {r.status_code}"
    forged = plain.get("/v1/participant/me", headers={**key, "X-Client-Cert": quote((certs / "bank.pem").read_text())})
    assert forged.status_code in (401, 403), "a client-sent X-Client-Cert header must be ignored"
    me = ok(bank_tls.get("/v1/participant/me", headers=key))
    assert me["mtls"], me
    print("mTLS: key alone refused, forged header refused, real client certificate accepted")

    mobile = "+9195" + str(uuid.uuid4().int)[:8]
    code = ok(plain.post("/v1/auth/otp", json={"mobile": mobile}), 202)["dev_code"]
    person = ok(plain.post("/v1/auth/verify", json={"mobile": mobile, "code": code, "display_name": "Smoke"}))
    assert person["new_user"]
    chk = ok(bank_tls.post("/v1/checks", headers=key, json={"mobile": mobile, "participant_txn_id": f"s-{run}",
                                                            "amount": 50_00, "payee": "shop@upi"}))
    print("person enrolled, payment check:", chk["status"])

    for _ in range(10):
        ok(plain.get("/healthz"))  # spread over both nodes; CI checks both logged requests
    nodes = {ok(plain.get("/v1/admin/audit/verify", headers=alice))["ok"] for _ in range(6)}
    assert nodes == {True}, "audit chain must verify from every node"
    print("audit chain verifies on every request")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "https://localhost:8443"))
