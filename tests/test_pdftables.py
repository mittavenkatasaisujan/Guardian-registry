"""Drafting a table from a PDF-only list (a review aid; never feeds a register directly)."""

import importlib.util
from pathlib import Path

import pytest

pytest.importorskip("pdfplumber")

from guardian_registry.pdftables import extract  # noqa: E402
from guardian_registry.tables import TableError  # noqa: E402

REF, NAME = "registration number|regn no", "name of the nbfc|company name"


def make_pdf(pages: list[list[tuple[float, float, str]]]) -> bytes:
    """A real PDF with text placed at (x, y) in points, Helvetica 9 pt (y from the bottom)."""
    objs = ["<< /Type /Catalog /Pages 2 0 R >>", None, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for items in pages:
        stream = "".join(
            f"BT /F1 9 Tf {x} {y} Td ({t.replace(chr(92), chr(92) * 2).replace('(', chr(92) + '(').replace(')', chr(92) + ')')}) Tj ET\n"
            for x, y, t in items).encode("latin-1")
        objs.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"endstream")
        content_no = len(objs)
        objs.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> "
                    f"/Contents {content_no} 0 R >>")
        kids.append(len(objs))
    objs[1] = f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>"
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, start=1):
        offsets.append(len(out))
        body = o if isinstance(o, bytes) else o.encode("latin-1")
        out += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(out)
    out += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    out += b"".join(f"{off:010d} 00000 n \n".encode() for off in offsets)
    out += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)


def table_page(rows, title=True, header=True, y0=720):
    items = []
    y = y0
    if title:
        items.append((60, y, "List of NBFCs registered with the Reserve Bank of India as on 31 October 2026"))
        y -= 30
    if header:
        items += [(60, y, "Sr. No."), (120, y, "Registration"), (300, y, "Name of the NBFC"), (480, y, "Region")]
        items += [(120, y - 11, "Number")]                     # a two-line header cell
        y -= 30
    for i, (ref, name, region) in enumerate(rows, start=1):
        items += [(60, y, str(i)), (120, y, ref), (300, y, name), (480, y, region)]
        y -= 14
    return items, y


def test_multi_page_with_wrapped_names_and_repeated_headers():
    p1, y = table_page([("N-14.03268", "Alpha Finance Ltd", "Mumbai"), ("N-14.03269", "Beta Capital Ltd", "Chennai")])
    p1 += [(300, y, "and Leasing")]                         # Beta's name wraps onto a second line
    p1 += [(60, y - 40, "Note: the list is updated monthly and may not be exhaustive.")]
    p2, _ = table_page([("N-14.03270", "Gamma Credit Ltd", "Delhi")], title=False)   # header repeated
    d = extract(make_pdf([p1, p2]), REF, NAME)
    assert [(r["regulator_ref"], r["name"]) for r in d.rows] == [
        ("N-14.03268", "Alpha Finance Ltd"), ("N-14.03269", "Beta Capital Ltd and Leasing"),
        ("N-14.03270", "Gamma Credit Ltd")]
    assert d.ok and d.pages == 2


def test_problems_are_reported_not_guessed():
    rows = [(f"N-14.0{3200 + i}", f"Company {i} Ltd", "Pune") for i in range(8)]
    rows += [("N-14.03201", "Duplicate Ltd", "Pune"), ("14O3999", "Odd Shape Ltd", "Pune")]
    p, y = table_page(rows)
    p += [(120, y, "N-14.09999"), (480, y, "Pune")]        # a number with no name
    d = extract(make_pdf([p]), REF, NAME)
    text = "\n".join(d.problems)
    assert "appears 2 times" in text and "doesn't look like the others" in text
    assert "licence number without name" in text
    assert not d.ok


def test_no_header():
    with pytest.raises(TableError, match="no header"):
        extract(make_pdf([[(60, 700, "Just some text")]]), REF, NAME)


def test_cli(tmp_path, capsys):
    p, _ = table_page([("N-14.03268", "Alpha Finance Ltd", "Mumbai")])
    pdf = tmp_path / "list.pdf"
    pdf.write_bytes(make_pdf([p]))
    spec = importlib.util.spec_from_file_location(
        "pdf_to_table", Path(__file__).resolve().parent.parent / "scripts" / "pdf_to_table.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = tmp_path / "draft.csv"
    assert mod.main([str(pdf), "--ref", REF, "--name", NAME, "--out", str(out)]) == 0
    assert "N-14.03268,Alpha Finance Ltd,1," in out.read_text()
