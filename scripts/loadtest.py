"""Load test: payment checks from many banks' worth of traffic, across several API nodes.

    python scripts/loadtest.py http://127.0.0.1:8000 http://127.0.0.1:8001 \\
        --admin alice:ci-alice-token,bob:ci-bob-token --people 200 --checks 4000 --concurrency 64 \\
        [--max-p95-ms 750] [--min-rps 50] [--json out.json]

Needs a registry with GR_OTP_DEV_ECHO=1 (to enrol test people) and generous rate limits
(GR_RATE_OTP, GR_RATE_CHECKS), since the test hammers them on purpose. Never point it at
production.

What it measures and checks:
  * throughput and latency (p50 / p95 / p99) of POST /v1/checks, spread over the nodes;
  * correctness under concurrency: each person has a daily limit, and checks for the same
    person race on different nodes. Afterwards, for every person, the total of the checks
    the registry let through (or held) must not exceed that limit: the per-person lock must
    hold even while every node is busy;
  * no 5xx errors, and the audit chain still verifies.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
import sys
import time
import uuid

import httpx

COUNTED = {"allowed", "cooling_off", "pending_approval", "approved"}
DAILY_LIMIT = 50_000_00          # ₹50,000 in paise
AMOUNTS = [500_00, 2_000_00, 7_500_00, 12_000_00]


def pct(values, p):
    if not values:
        return 0.0
    values = sorted(values)
    k = max(0, min(len(values) - 1, int(round(p / 100 * (len(values) - 1)))))
    return values[k]


async def main_async(a) -> int:
    ops = dict(x.split(":", 1) for x in a.admin.split(","))
    op1, op2 = ({"X-Admin-Token": t} for t in list(ops.values())[:2])
    nodes = [httpx.AsyncClient(base_url=b, timeout=30, limits=httpx.Limits(max_connections=a.concurrency))
             for b in a.base]
    first = nodes[0]

    async def ok(coro, code=200):
        r = await coro
        if r.status_code != code:
            raise SystemExit(f"setup failed: {r.request.method} {r.request.url.path} {r.status_code} {r.text[:200]}")
        return r.json() if r.content else {}

    run = uuid.uuid4().hex[:6]
    ref = f"RBI-LOAD-{run}"
    await ok(first.put("/v1/admin/register/bank", headers=op1, json={
        "source": "load test", "as_of": "2026-11-23", "entities": [{"regulator_ref": ref, "name": "Load Bank"}]}))
    p = await ok(first.post("/v1/admin/participants", headers=op1,
                            json={"name": f"Load Bank {run}", "kind": "bank", "regulator_ref": ref}), 201)
    if p["status"] != "active":
        await ok(first.post(f"/v1/admin/participants/{p['participant_id']}/approve", headers=op2))
    bank = {"X-Api-Key": p["api_key"]}

    print(f"enrolling {a.people} people ...", flush=True)
    sem = asyncio.Semaphore(16)
    base_digits = random.randint(10_000_000, 89_999_999)
    mobiles = [f"+9193{base_digits + i:08d}" for i in range(a.people)]

    async def enrol(m):
        async with sem:
            code = (await ok(first.post("/v1/auth/otp", json={"mobile": m}), 202))["dev_code"]
            tok = (await ok(first.post("/v1/auth/verify", json={"mobile": m, "code": code,
                                                                 "display_name": "Load", "adult": True})))["token"]
            await ok(first.patch("/v1/me/rules", headers={"Authorization": f"Bearer {tok}"},
                                 json={"daily_limit": DAILY_LIMIT}))
    await asyncio.gather(*(enrol(m) for m in mobiles))

    print(f"firing {a.checks} checks at concurrency {a.concurrency} over {len(nodes)} node(s) ...", flush=True)
    lat, statuses, errors = [], [], []
    spent: dict[str, int] = {m: 0 for m in mobiles}
    work = asyncio.Queue()
    hot = mobiles[: max(1, a.people // 10)]  # a tenth of people get half the traffic: same-person races
    for i in range(a.checks):
        m = random.choice(hot) if i % 2 else random.choice(mobiles)
        work.put_nowait((i, m, random.choice(AMOUNTS)))

    async def worker(w):
        client = nodes[w % len(nodes)]
        while True:
            try:
                i, m, amount = work.get_nowait()
            except asyncio.QueueEmpty:
                return
            t0 = time.perf_counter()
            try:
                r = await client.post("/v1/checks", headers=bank, json={
                    "mobile": m, "participant_txn_id": f"{run}-{i}", "amount": amount,
                    "payee": f"shop{i % 7}@upi"})
            except httpx.HTTPError as e:
                errors.append(f"transport: {e}")
                continue
            lat.append((time.perf_counter() - t0) * 1000)
            if r.status_code >= 500 or r.status_code not in (200, 201):
                errors.append(f"{r.status_code} {r.text[:120]}")
                continue
            st = r.json()["status"]
            statuses.append(st)
            if st in COUNTED:
                spent[m] += amount

    t0 = time.perf_counter()
    await asyncio.gather(*(worker(w) for w in range(a.concurrency)))
    wall = time.perf_counter() - t0

    over = {m: v for m, v in spent.items() if v > DAILY_LIMIT}
    audit = await ok(first.get("/v1/admin/audit/verify", headers=op1))
    for n in nodes:
        await n.aclose()

    result = {
        "checks": a.checks, "nodes": len(nodes), "concurrency": a.concurrency, "seconds": round(wall, 2),
        "rps": round(len(lat) / wall, 1) if wall else 0,
        "p50_ms": round(pct(lat, 50), 1), "p95_ms": round(pct(lat, 95), 1), "p99_ms": round(pct(lat, 99), 1),
        "mean_ms": round(statistics.fmean(lat), 1) if lat else 0,
        "errors": len(errors), "statuses": {s: statuses.count(s) for s in sorted(set(statuses))},
        "people_over_daily_limit": len(over), "audit_ok": audit["ok"], "audit_entries": audit["entries"],
    }
    print(json.dumps(result, indent=2))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(result, f, indent=2)
    problems = []
    if errors:
        problems.append(f"{len(errors)} errors, e.g. {errors[:3]}")
    if over:
        problems.append(f"{len(over)} people went over their daily limit: {list(over.items())[:3]}")
    if not audit["ok"]:
        problems.append("audit chain does not verify")
    if a.max_p95_ms and result["p95_ms"] > a.max_p95_ms:
        problems.append(f"p95 {result['p95_ms']} ms > {a.max_p95_ms} ms")
    if a.min_rps and result["rps"] < a.min_rps:
        problems.append(f"{result['rps']} checks/s < {a.min_rps}")
    if problems:
        print("FAIL: " + "; ".join(problems))
        return 1
    print("ok")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base", nargs="+", help="one URL per API node")
    ap.add_argument("--admin", required=True, help="two operators, name:token,name:token")
    ap.add_argument("--people", type=int, default=200)
    ap.add_argument("--checks", type=int, default=4000)
    ap.add_argument("--concurrency", type=int, default=64)
    ap.add_argument("--max-p95-ms", type=float)
    ap.add_argument("--min-rps", type=float)
    ap.add_argument("--json")
    return asyncio.run(main_async(ap.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
