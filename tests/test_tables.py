"""Reading published registers: .xlsx without a spreadsheet library, messy headers, and the
signed-mirror tool."""

import base64
import io
import json
import zipfile

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from guardian_registry import mirror, tables
from guardian_registry.registerfeed import FeedError, parse_feed

openpyxl = pytest.importorskip("openpyxl")  # used only to write real workbooks to read back

REF, NAME = "registration number|regn no", "name of the nbfc|company name"


def workbook(sheets: dict[str, list[list]]) -> bytes:
    """A real .xlsx, written by openpyxl (an independent implementation of the format)."""
    wb = openpyxl.Workbook()
    wb.remove(wb.active)
    for title, rows in sheets.items():
        ws = wb.create_sheet(title)
        for r in rows:
            ws.append(r)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


RBI_LIKE = [
    ["Reserve Bank of India"],
    ["List of NBFCs registered with RBI as on 31 October 2026"],
    [],
    ["Sr. No.", "Name of the NBFC ", "Registration\nNumber", "Regional Office"],
    [1, "Alpha Finance  Ltd", "N-14.03268", "Mumbai"],
    [2, "Beta Capital Ltd", 1403269, "Chennai"],          # a number in the licence column
    [3, "Gamma Leasing Ltd", "N-14.03270", None],
    [4, "Alpha Finance Ltd (dup)", "N-14.03268", "Mumbai"],
    [],
    ["Note: the list is updated monthly and is not exhaustive."],
]


class TestXlsx:
    def test_rbi_like_sheet(self):
        out, _ = parse_feed(workbook({"NBFC List": RBI_LIKE}), "xlsx", REF, NAME)
        assert out == [{"regulator_ref": "N-14.03268", "name": "Alpha Finance Ltd"},
                       {"regulator_ref": "1403269", "name": "Beta Capital Ltd"},
                       {"regulator_ref": "N-14.03270", "name": "Gamma Leasing Ltd"}]

    def test_named_sheet(self):
        raw = workbook({"Cover": [["Read me"]], "Banks": [["Licence No", "Bank"], ["L-1", "One Bank"]]})
        assert parse_feed(raw, "xlsx", "licence no", "bank", sheet="banks")[0] == [
            {"regulator_ref": "L-1", "name": "One Bank"}]
        with pytest.raises(FeedError, match="no sheet named 'Nope'.*Cover, Banks"):
            parse_feed(raw, "xlsx", "licence no", "bank", sheet="Nope")
        with pytest.raises(FeedError, match="no header row"):
            parse_feed(raw, "xlsx", "licence no", "bank")       # first sheet is the cover

    def test_half_filled_row_is_an_error_not_a_silent_drop(self):
        raw = workbook({"S": [["Regn No", "Company Name"], ["A-1", "Alpha"], ["A-2", None]]})
        with pytest.raises(FeedError, match="row 3 has a reference but no name"):
            parse_feed(raw, "xlsx", REF, NAME)

    def test_inline_strings_and_sparse_cells(self):
        """Some exporters write inline strings and skip empty cells; read those too."""
        sheet = ('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
                 '<row r="1"><c r="B1" t="inlineStr"><is><t>Regn No</t></is></c>'
                 '<c r="D1" t="inlineStr"><is><t>Company Name</t></is></c></row>'
                 '<row r="2"><c r="B2"><v>42.0</v></c><c r="D2" t="inlineStr"><is><t>Forty Two</t></is></c></row>'
                 '</sheetData></worksheet>')
        assert tables.records(tables.xlsx_rows(_zip(sheet)), REF, NAME) == [
            {"regulator_ref": "42", "name": "Forty Two"}]

    def test_not_a_workbook_and_zip_bombs(self, monkeypatch):
        with pytest.raises(FeedError, match="not an .xlsx"):
            parse_feed(b"PK\x03\x04 nope", "xlsx", REF, NAME)
        monkeypatch.setattr(tables, "MAX_XLSX_UNCOMPRESSED", 1000)
        with pytest.raises(FeedError, match="too large"):
            parse_feed(workbook({"S": [["x" * 2000]]}), "xlsx", REF, NAME)


def _zip(sheet_xml: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("xl/workbook.xml",
                   '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                   '<sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>')
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Target="worksheets/sheet1.xml" '
                   'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"/>'
                   '</Relationships>')
        z.writestr("xl/worksheets/sheet1.xml", sheet_xml)
    return buf.getvalue()


class TestCsv:
    def test_title_rows_and_windows_encoding(self):
        raw = "List of payment banks\r\n\r\nLicence No.,Name of Bank\r\nPB-1,Caf\xe9 Payments Bank\r\n".encode("cp1252")
        assert parse_feed(raw, "csv", "licence no", "name of bank")[0] == [
            {"regulator_ref": "PB-1", "name": "Café Payments Bank"}]


class TestMirror:
    def test_build_sign_and_the_registry_accepts_it(self, reg):
        pem, pub = mirror.keygen()
        key = mirror.load_private_key(pem)
        body, ents = mirror.build(workbook({"NBFC List": RBI_LIKE}), "xlsx", REF, NAME,
                                  "https://rbi.org.in/nbfc-list.xlsx", "2026-10-31")
        again, _ = mirror.build(workbook({"NBFC List": RBI_LIKE}), "xlsx", REF, NAME,
                                "https://rbi.org.in/nbfc-list.xlsx", "2026-10-31")
        assert body == again                                    # deterministic: unchanged list, same hash
        doc = json.loads(body)
        assert doc["as_of"] == "2026-10-31" and [e["regulator_ref"] for e in doc["entities"]] == sorted(
            e["regulator_ref"] for e in ents)
        sig = mirror.sign(body, key)
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(base64.b64decode(sig), body)

        url = "https://lists.example.in/nbfc.json"
        files = {url: body, url + ".sig": sig}
        reg.feed_http = httpx.Client(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, content=files[str(r.url)]) if str(r.url) in files else httpx.Response(404)))
        reg.configure_feed("alice", "nbfc", url, "json", public_key=pub)
        reg.approve_feed("bob", "nbfc")
        assert reg.refresh_registers() == {"nbfc": "updated"}
        st = [s for s in reg.register_status() if s["kind"] == "nbfc"][0]
        assert st["entities"] == 3 and st["as_of"] == "2026-10-31"

    def test_diff(self):
        _, ents = mirror.build(b"regn no,company name\nA,Alpha\nB,Beta Ltd\n", "csv", REF, NAME, "s", "d")
        prev, _ = mirror.build(b"regn no,company name\nB,Beta\nC,Gamma\n", "csv", REF, NAME, "s", "d")
        assert mirror.diff(prev, ents) == {"added": ["A"], "removed": ["C"], "renamed": ["B"]}

    def test_refuses_empty_lists_and_missing_provenance(self):
        with pytest.raises(ValueError, match="no entities"):
            mirror.build(b"regn no,company name\n", "csv", REF, NAME, "s", "d")
        with pytest.raises(ValueError, match="source and as_of"):
            mirror.build(b"regn no,company name\nA,B\n", "csv", REF, NAME, "", "d")

    def test_cli(self, tmp_path, capsys):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "mirror_register", __file__.replace("tests", "scripts").replace("test_tables.py", "mirror_register.py"))
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        key = tmp_path / "k.pem"
        assert cli.main(["keygen", "--private", str(key)]) == 0
        with pytest.raises(FileExistsError):
            cli.main(["keygen", "--private", str(key)])
        src = tmp_path / "list.xlsx"
        src.write_bytes(workbook({"NBFC List": RBI_LIKE}))
        out = tmp_path / "nbfc.json"
        args = ["build", str(src), "--ref", REF, "--name", NAME, "--source-url", "https://rbi.org.in/x",
                "--as-of", "2026-10-31", "--key", str(key), "--out", str(out)]
        assert cli.main(args) == 0 and (tmp_path / "nbfc.json.sig").exists()
        # next month the export is broken and two of three NBFCs vanish: stop before publishing
        src.write_bytes(workbook({"NBFC List": RBI_LIKE[:5]}))
        before = out.read_bytes()
        assert cli.main(args + ["--previous", str(out)]) == 3
        assert out.read_bytes() == before
        assert "would disappear" in capsys.readouterr().err
        assert cli.main(args + ["--previous", str(out), "--force"]) == 0
