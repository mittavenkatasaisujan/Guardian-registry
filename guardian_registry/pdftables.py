"""Turn a regulator's PDF-only list into a DRAFT table for a person to check.

PDF has no tables, only words at positions, so this is a best effort: it finds the header
row (licence-number and name columns, matched like tables.py), cuts the page into columns
at the header cells, assigns every word below to a column, joins names that wrap onto a
second line, skips headers repeated on later pages, and reports anything doubtful:

  * a row with a licence number but no name, or a name but no number;
  * repeated licence numbers;
  * licence numbers that don't look like the others (a different shape: letters vs digits);
  * pages where no row was found.

It never feeds a register directly. The output is a CSV for scripts/mirror_register.py, made
only after a person has read the report and checked the flagged rows against the PDF:
a misread licence number would suspend a bank.

Needs pdfplumber (a tool dependency, not a server one): pip install pdfplumber.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field

from .tables import TableError, norm

LINE_TOLERANCE = 3.0      # points: words this close vertically are one line
CELL_GAP = 12.0           # points: a gap this wide between header words starts a new cell


@dataclass
class Draft:
    rows: list[dict] = field(default_factory=list)       # {"regulator_ref", "name", "page", "line"}
    problems: list[str] = field(default_factory=list)
    pages: int = 0

    @property
    def ok(self) -> bool:
        return not self.problems


def _lines(words: list[dict]) -> list[list[dict]]:
    out: list[list[dict]] = []
    for w in sorted(words, key=lambda w: (round(w["top"]), w["x0"])):
        if out and abs(out[-1][0]["top"] - w["top"]) <= LINE_TOLERANCE:
            out[-1].append(w)
        else:
            out.append([w])
    return [sorted(line, key=lambda w: w["x0"]) for line in out]


def _cells(line: list[dict]) -> list[dict]:
    cells: list[dict] = []
    for w in line:
        if cells and w["x0"] - cells[-1]["x1"] <= CELL_GAP:
            cells[-1]["text"] += " " + w["text"]
            cells[-1]["x1"] = w["x1"]
        else:
            cells.append({"text": w["text"], "x0": w["x0"], "x1": w["x1"]})
    return cells


def _merge_header(a: list[dict], b: list[dict]) -> list[dict]:
    """Two-line headers ("Registration" over "Number"): join cells that overlap horizontally."""
    out = [dict(c) for c in a]
    for c in b:
        hit = next((o for o in out if c["x0"] < o["x1"] + CELL_GAP and c["x1"] > o["x0"] - CELL_GAP), None)
        if hit:
            hit["text"] += " " + c["text"]
            hit["x0"], hit["x1"] = min(hit["x0"], c["x0"]), max(hit["x1"], c["x1"])
        else:
            out.append(dict(c))
    return sorted(out, key=lambda c: c["x0"])


def _find(cells: list[dict], field_: str) -> int | None:
    alts = {norm(f) for f in field_.split("|") if norm(f)}
    return next((i for i, c in enumerate(cells) if norm(c["text"]) in alts), None)


def _header(lines: list[list[dict]], ref: str, name: str):
    for i, line in enumerate(lines[:60]):
        for span in (1, 2):
            cells = _cells(line) if span == 1 else (
                _merge_header(_cells(line), _cells(lines[i + 1])) if i + 1 < len(lines) else None)
            if not cells:
                continue
            r, n = _find(cells, ref), _find(cells, name)
            if r is not None and n is not None and r != n:
                return i + span, cells, r, n
    return None


def _shape(ref: str) -> str:
    return re.sub(r"[0-9]+", "9", re.sub(r"[A-Za-z]+", "A", ref))


def extract(pdf_bytes: bytes, ref_field: str, name_field: str) -> Draft:
    try:
        import pdfplumber
    except ImportError:
        raise TableError("PDF extraction needs pdfplumber: pip install pdfplumber") from None
    import io
    draft = Draft()
    header_cells = rc = nc = None
    header_norm = None
    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
        draft.pages = len(pdf.pages)
        for pno, page in enumerate(pdf.pages, start=1):
            lines = _lines(page.extract_words(x_tolerance=1.5, y_tolerance=2))
            start = 0
            found = _header(lines, ref_field, name_field)
            if found:
                start, header_cells, rc, nc = found
                header_norm = norm(" ".join(c["text"] for c in header_cells))
            elif header_cells is None:
                continue
            bounds = [c["x0"] for c in header_cells]
            before = len(draft.rows)
            for lno, line in enumerate(lines[start:], start=start + 1):
                if norm(" ".join(w["text"] for w in line)) == header_norm:
                    continue  # header repeated on this page
                cols = [""] * len(header_cells)
                for w in line:
                    centre = (w["x0"] + w["x1"]) / 2
                    k = max((j for j, b in enumerate(bounds) if centre >= b - CELL_GAP), default=0)
                    cols[k] = (cols[k] + " " + w["text"]).strip()
                if len(_cells(line)) == 1 and len(line) >= 3:
                    continue  # one run of text with no column gaps: a title or footnote across the page
                ref, nm = cols[rc].strip(), cols[nc].strip()
                if not ref and not nm:
                    continue
                if not ref and nm and draft.rows and len(line) <= 6 and len([c for c in cols if c]) == 1:
                    draft.rows[-1]["name"] += " " + nm  # a name wrapped onto the next line
                    continue
                filled = [c for c in cols if c]
                if len(filled) == 1 and len(filled[0].split()) >= 3:
                    continue  # a title or footnote across the page
                if not ref or not nm:
                    draft.problems.append(f"page {pno}, line {lno}: {'name' if nm else 'licence number'} without "
                                          f"{'licence number' if nm else 'name'}: {' | '.join(filled)}")
                    continue
                draft.rows.append({"regulator_ref": ref, "name": " ".join(nm.split()), "page": pno, "line": lno})
            if found is None and len(draft.rows) == before:
                draft.problems.append(f"page {pno}: no rows found (check this page by hand)")
    if header_cells is None:
        raise TableError(f"no header with columns {ref_field!r} and {name_field!r} found in the PDF")
    counts = Counter(r["regulator_ref"] for r in draft.rows)
    for ref, n in counts.items():
        if n > 1:
            draft.problems.append(f"licence number {ref} appears {n} times")
    shapes = Counter(_shape(r["regulator_ref"]) for r in draft.rows)
    if shapes:
        common, common_n = shapes.most_common(1)[0]
        if common_n >= max(5, len(draft.rows) * 0.6):
            for r in draft.rows:
                if _shape(r["regulator_ref"]) != common:
                    draft.problems.append(f"page {r['page']}, line {r['line']}: licence number "
                                          f"{r['regulator_ref']!r} doesn't look like the others ({common!r})")
    return draft
