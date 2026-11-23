"""Rebuild every configured register mirror in one go (the monthly job runs this).

    python scripts/mirror_all.py deploy/register-sources.json --key mirror-key.pem --out site/registers

register-sources.json lists the official lists to mirror:

    {"sources": [
      {"kind": "nbfc", "source_url": "https://...xlsx", "format": "xlsx", "sheet": null,
       "ref": "registration number|regn no", "name": "name of the nbfc|company name", "as_of": "auto"}
    ]}

For each source with a source_url: download it, build the signed mirror <kind>.json (+ .sig)
in --out, compare with the mirror already there and STOP for that source (exit code 3,
nothing written) if more than --max-drop-pct of its entities would disappear. Sources
without a source_url are skipped with a note. "as_of": "auto" uses today's date (UTC).
Exit codes: 0 all good, 2 a source failed to download or parse, 3 a source was held.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import httpx  # noqa: E402

from guardian_registry import mirror  # noqa: E402
from guardian_registry.registerfeed import FeedError  # noqa: E402


def fetch(url: str) -> bytes:
    if url.startswith("https://"):
        r = httpx.get(url, timeout=120, follow_redirects=True, headers={"User-Agent": "guardian-registry-mirror"})
        r.raise_for_status()
        return r.content
    if url.startswith("http://"):
        raise ValueError("refusing a plain http source")
    with open(url, "rb") as f:  # a local file (tests, or a manually downloaded list)
        return f.read()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("sources")
    ap.add_argument("--key", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-drop-pct", type=float, default=5)
    a = ap.parse_args(argv)
    with open(a.sources, encoding="utf-8") as f:
        sources = json.load(f)["sources"]
    with open(a.key, "rb") as f:
        key = mirror.load_private_key(f.read())
    os.makedirs(a.out, exist_ok=True)
    today = datetime.now(timezone.utc).date().isoformat()
    worst = 0
    for s in sources:
        kind = s["kind"]
        if not s.get("source_url"):
            print(f"[{kind}] skipped: no source_url configured")
            continue
        out = os.path.join(a.out, f"{kind}.json")
        try:
            body, ents = mirror.build(fetch(s["source_url"]), s.get("format", "xlsx"), s["ref"], s["name"],
                                      s["source_url"], today if s.get("as_of", "auto") == "auto" else s["as_of"],
                                      s.get("sheet"))
        except (FeedError, ValueError, OSError, httpx.HTTPError) as e:
            print(f"[{kind}] FAILED: {e}")
            worst = max(worst, 2)
            continue
        previous = open(out, "rb").read() if os.path.exists(out) else None
        d = mirror.diff(previous, ents)
        if previous:
            old = len(ents) - len(d["added"]) + len(d["removed"])
            if old and len(d["removed"]) * 100 > a.max_drop_pct * old:
                print(f"[{kind}] HELD: {len(d['removed'])} of {old} entities would disappear "
                      f"(more than {a.max_drop_pct}%); nothing written. Check the source, then publish by hand.")
                worst = max(worst, 3)
                continue
            if json.loads(previous)["entities"] == json.loads(body)["entities"]:
                print(f"[{kind}] unchanged ({len(ents)} entities)")
                continue
        with open(out, "wb") as f:
            f.write(body)
        with open(out + ".sig", "wb") as f:
            f.write(mirror.sign(body, key))
        print(f"[{kind}] {len(ents)} entities; +{len(d['added'])} -{len(d['removed'])} ~{len(d['renamed'])}")
    return worst


if __name__ == "__main__":
    sys.exit(main())
