"""Read the tables regulators actually publish: CSV and Excel (.xlsx), with title rows,
merged-looking headers and licence numbers stored as numbers.

  * rows(raw, fmt, sheet)        -> list of rows (lists of strings)
  * records(rows, ref, name)     -> [{"regulator_ref", "name"}], finding the header row

The .xlsx reader uses only the standard library (a workbook is a zip of XML parts), so
there's no spreadsheet dependency to keep patched. It refuses oversized or zip-bomb files.

Header matching is forgiving, because published headers look like "Registration\\nNo." or
"Name of the NBFC ": both sides are lower-cased and every run of non-letters/digits becomes
one space. A field can list alternatives with "|", e.g. "registration number|regn no".
"""

from __future__ import annotations

import csv
import io
import re
import zipfile
from xml.etree import ElementTree as ET

MAX_XLSX_UNCOMPRESSED = 200 * 1024 * 1024
MAX_XLSX_MEMBERS = 2000
HEADER_SEARCH_ROWS = 50
NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
      "rel": "http://schemas.openxmlformats.org/package/2006/relationships"}


class TableError(Exception):
    pass


def norm(text: str) -> str:
    return re.sub(r"[^0-9a-z]+", " ", str(text).lower()).strip()


# ------------------------------------------------------------------ CSV
def csv_rows(raw: bytes) -> list[list[str]]:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text = raw.decode("cp1252")  # Excel's "CSV" on Windows
        except UnicodeDecodeError:
            raise TableError("list is neither UTF-8 nor Windows-1252 text") from None
    return [[c.strip() for c in r] for r in csv.reader(io.StringIO(text))]


# ------------------------------------------------------------------ XLSX
def _col_index(ref: str) -> int:
    n = 0
    for ch in ref:
        if ch.isalpha():
            n = n * 26 + (ord(ch.upper()) - 64)
        else:
            break
    return n - 1


def _number_text(v: str) -> str:
    """Excel stores 1234 as "1234" or "1234.0"; licence numbers must not grow a ".0"."""
    try:
        f = float(v)
    except ValueError:
        return v
    if f.is_integer() and abs(f) < 1e15:
        return str(int(f))
    return v


def xlsx_rows(raw: bytes, sheet: str | None = None) -> list[list[str]]:
    try:
        z = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile:
        raise TableError("not an .xlsx file") from None
    infos = z.infolist()
    if len(infos) > MAX_XLSX_MEMBERS or sum(i.file_size for i in infos) > MAX_XLSX_UNCOMPRESSED:
        raise TableError("spreadsheet is too large when unpacked")

    def xml(name: str):
        try:
            return ET.fromstring(z.read(name))
        except KeyError:
            return None
        except ET.ParseError:
            raise TableError(f"{name} is not valid XML") from None

    wb = xml("xl/workbook.xml")
    if wb is None:
        raise TableError("spreadsheet has no workbook")
    sheets = [(s.get("name"), s.get(f"{{{NS['r']}}}id")) for s in wb.iterfind("m:sheets/m:sheet", NS)]
    if not sheets:
        raise TableError("spreadsheet has no sheets")
    if sheet:
        match = [s for s in sheets if norm(s[0]) == norm(sheet)]
        if not match:
            raise TableError(f"no sheet named {sheet!r} (sheets: {', '.join(s[0] for s in sheets)})")
        rid = match[0][1]
    else:
        rid = sheets[0][1]
    rels = xml("xl/_rels/workbook.xml.rels")
    target = None
    if rels is not None:
        for r in rels.iterfind("rel:Relationship", NS):
            if r.get("Id") == rid:
                target = r.get("Target")
    if not target:
        raise TableError("can't find the sheet's part in the workbook")
    target = target.lstrip("/")
    path = target if target.startswith("xl/") else "xl/" + target

    shared: list[str] = []
    sst = xml("xl/sharedStrings.xml")
    if sst is not None:
        for si in sst.iterfind("m:si", NS):
            shared.append("".join(t.text or "" for t in si.iter(f"{{{NS['m']}}}t")))

    ws = xml(path)
    if ws is None:
        raise TableError(f"sheet part {path} is missing")
    out: list[list[str]] = []
    for row in ws.iterfind("m:sheetData/m:row", NS):
        cells: dict[int, str] = {}
        auto = 0
        for c in row.iterfind("m:c", NS):
            idx = _col_index(c.get("r")) if c.get("r") else auto
            auto = idx + 1
            t = c.get("t")
            if t == "inlineStr":
                val = "".join(x.text or "" for x in c.iter(f"{{{NS['m']}}}t"))
            else:
                v = c.find("m:v", NS)
                val = v.text if v is not None and v.text is not None else ""
                if t == "s":
                    try:
                        val = shared[int(val)]
                    except (ValueError, IndexError):
                        raise TableError("cell points at a missing shared string") from None
                elif t == "b":
                    val = "TRUE" if val == "1" else "FALSE"
                elif t in (None, "n"):
                    val = _number_text(val)
            cells[idx] = val.strip()
        if cells:
            width = max(cells) + 1
            out.append([cells.get(i, "") for i in range(width)])
        else:
            out.append([])
    return out


def rows(raw: bytes, fmt: str, sheet: str | None = None) -> list[list[str]]:
    if fmt == "csv":
        return csv_rows(raw)
    if fmt == "xlsx":
        return xlsx_rows(raw, sheet)
    raise TableError(f"unsupported table format {fmt!r}")


# ------------------------------------------------------------------ header + records
def _alternatives(field: str) -> set[str]:
    return {norm(f) for f in field.split("|") if norm(f)}


def find_header(table: list[list[str]], ref_field: str, name_field: str) -> tuple[int, int, int]:
    """(header row index, ref column, name column). The header is the first row, among the
    first HEADER_SEARCH_ROWS, that has both a ref column and a name column."""
    refs, names = _alternatives(ref_field), _alternatives(name_field)
    for i, row in enumerate(table[:HEADER_SEARCH_ROWS]):
        cells = [norm(c) for c in row]
        r = next((j for j, c in enumerate(cells) if c in refs), None)
        n = next((j for j, c in enumerate(cells) if c in names and j != r), None)
        if r is not None and n is not None:
            return i, r, n
    raise TableError(f"no header row with columns {ref_field!r} and {name_field!r} in the first "
                     f"{HEADER_SEARCH_ROWS} rows")


def records(table: list[list[str]], ref_field: str, name_field: str) -> list[dict]:
    """Entities under the header. Blank rows are skipped, as are rows with neither value
    (section titles, footnotes after the table); a row with only one of them is an error,
    because silently dropping a licence would suspend a bank. Repeated refs keep the first."""
    h, rc, nc = find_header(table, ref_field, name_field)
    out, seen = [], set()
    for k, row in enumerate(table[h + 1:], start=h + 2):
        ref = row[rc].strip() if rc < len(row) else ""
        name = row[nc].strip() if nc < len(row) else ""
        if not ref and not name:
            continue
        if not ref or not name:
            filled = [c for c in row if c.strip()]
            if len(filled) == 1 and len(filled[0].split()) >= 3:
                continue  # a lone sentence: a section title or footnote ("Note: list as on ...")
            raise TableError(f"row {k} has a {'name' if name else 'reference'} but no "
                             f"{'reference' if name else 'name'}")
        if ref in seen:
            continue
        seen.add(ref)
        out.append({"regulator_ref": ref, "name": " ".join(name.split())})
    return out
