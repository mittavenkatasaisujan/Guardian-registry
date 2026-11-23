"""Draft a CSV from a regulator's PDF-only list, with a report of rows to check by hand.

    python scripts/pdf_to_table.py list.pdf --ref "registration number|regn no" \\
        --name "name of the nbfc|company name" --out nbfc-draft.csv

Writes the draft CSV (regulator_ref, name, page, line) and prints a report. Exit code 1 when
the report lists problems: read them against the PDF, fix the CSV, then build the signed
mirror from it with scripts/mirror_register.py build nbfc-draft.csv --format csv
--ref regulator_ref --name name ... . Needs: pip install pdfplumber
"""

from __future__ import annotations

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from guardian_registry.pdftables import extract  # noqa: E402
from guardian_registry.tables import TableError  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pdf")
    ap.add_argument("--ref", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    with open(a.pdf, "rb") as f:
        raw = f.read()
    try:
        draft = extract(raw, a.ref, a.name)
    except TableError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["regulator_ref", "name", "page", "line"])
        for r in draft.rows:
            w.writerow([r["regulator_ref"], r["name"], r["page"], r["line"]])
    print(f"{len(draft.rows)} rows from {draft.pages} pages -> {a.out}")
    if draft.problems:
        print(f"\n{len(draft.problems)} things to check against the PDF before using this list:")
        for p in draft.problems:
            print(f"  - {p}")
        return 1
    print("no problems found; still compare a sample of rows with the PDF before publishing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
