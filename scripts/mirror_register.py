"""Make a signed mirror of an official list for a Guardian Registry register feed.

  python scripts/mirror_register.py keygen --private mirror-key.pem
      Makes an Ed25519 signing key and prints the public key to put in the feed.

  python scripts/mirror_register.py build SOURCE --format xlsx --ref "registration number|regn no" \\
        --name "name of the nbfc|company name" --source-url https://rbi.org.in/... --as-of 2026-11-01 \\
        --key mirror-key.pem --out nbfc.json [--sheet "NBFC List"] [--previous nbfc.json] [--max-drop-pct 5]
      SOURCE is a file or an https URL (.xlsx, .csv or .json). Writes nbfc.json and nbfc.json.sig,
      and prints what changed since --previous. Stops, writing nothing, if more than
      --max-drop-pct of the previous entities would disappear (use --force after checking).

Then publish both files on any static host and configure the feed:
  PUT /v1/admin/register-feeds/nbfc
      {"url": "https://lists.example.in/nbfc.json", "format": "json", "public_key": "<printed key>"}
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import httpx  # noqa: E402

from guardian_registry import mirror  # noqa: E402
from guardian_registry.registerfeed import FeedError  # noqa: E402


def _read(source: str) -> bytes:
    if source.startswith("https://"):
        r = httpx.get(source, timeout=60, follow_redirects=True)
        r.raise_for_status()
        return r.content
    if source.startswith("http://"):
        raise SystemExit("refusing a plain http source; use https or download it first")
    with open(source, "rb") as f:
        return f.read()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen")
    k.add_argument("--private", required=True, help="where to write the private key (never publish it)")
    b = sub.add_parser("build")
    b.add_argument("source")
    b.add_argument("--format", choices=["xlsx", "csv", "json"])
    b.add_argument("--sheet")
    b.add_argument("--ref", required=True, help="licence-number column header; alternatives with |")
    b.add_argument("--name", required=True, help="name column header; alternatives with |")
    b.add_argument("--source-url", required=True, help="the regulator's page or file this came from")
    b.add_argument("--as-of", required=True, help="date of the published list")
    b.add_argument("--key", required=True, help="private key from keygen")
    b.add_argument("--out", required=True)
    b.add_argument("--previous", help="the last published mirror, to show and check the changes")
    b.add_argument("--max-drop-pct", type=float, default=5)
    b.add_argument("--force", action="store_true", help="publish even if many entities disappear")
    a = ap.parse_args(argv)

    if a.cmd == "keygen":
        pem, pub = mirror.keygen()
        mirror.write_private_key(a.private, pem)
        print(f"private key written to {a.private} (keep it secret, back it up)")
        print(f"public key for the feed: {pub}")
        return 0

    fmt = a.format or os.path.splitext(a.source.split("?")[0])[1].lstrip(".").lower()
    if fmt not in ("xlsx", "csv", "json"):
        raise SystemExit("say --format xlsx, csv or json")
    with open(a.key, "rb") as f:
        key = mirror.load_private_key(f.read())
    try:
        body, entities = mirror.build(_read(a.source), fmt, a.ref, a.name, a.source_url, a.as_of, a.sheet)
    except (FeedError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    previous = None
    if a.previous and os.path.exists(a.previous):
        with open(a.previous, "rb") as f:
            previous = f.read()
    d = mirror.diff(previous, entities)
    print(f"{len(entities)} entities; +{len(d['added'])} added, -{len(d['removed'])} removed, "
          f"{len(d['renamed'])} renamed")
    for label in ("removed", "renamed"):
        if d[label]:
            print(f"  {label}: {', '.join(d[label][:20])}{' ...' if len(d[label]) > 20 else ''}")
    if previous:
        old = len(entities) - len(d["added"]) + len(d["removed"])
        if old and len(d["removed"]) * 100 > a.max_drop_pct * old and not a.force:
            print(f"error: {len(d['removed'])} of {old} entities would disappear (more than {a.max_drop_pct}%). "
                  "Check the source; re-run with --force if it is right.", file=sys.stderr)
            return 3
    with open(a.out, "wb") as f:
        f.write(body)
    with open(a.out + ".sig", "wb") as f:
        f.write(mirror.sign(body, key))
    print(f"wrote {a.out} and {a.out}.sig; signed by {mirror.public_key_b64(key)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
