"""The monthly mirror job (scripts/mirror_all.py)."""

import importlib.util
import json
from pathlib import Path

from guardian_registry import mirror

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "mirror_all.py"


def load():
    spec = importlib.util.spec_from_file_location("mirror_all", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def setup(tmp_path, rows):
    src = tmp_path / "nbfc.csv"
    src.write_text("Regn No,Company Name\n" + "".join(f"N-{i},Company {i}\n" for i in rows))
    sources = tmp_path / "sources.json"
    sources.write_text(json.dumps({"sources": [
        {"kind": "nbfc", "source_url": str(src), "format": "csv", "ref": "regn no", "name": "company name"},
        {"kind": "bank", "source_url": "", "format": "xlsx", "ref": "x", "name": "y"}]}))
    pem, _ = mirror.keygen()
    key = tmp_path / "k.pem"
    key.write_bytes(pem)
    return src, sources, key, tmp_path / "site"


def test_build_unchanged_and_held(tmp_path, capsys):
    src, sources, key, site = setup(tmp_path, range(40))
    run = load().main
    assert run([str(sources), "--key", str(key), "--out", str(site)]) == 0
    out = capsys.readouterr().out
    assert "[nbfc] 40 entities" in out and "[bank] skipped" in out
    assert (site / "nbfc.json.sig").exists()
    first = (site / "nbfc.json").read_bytes()

    assert run([str(sources), "--key", str(key), "--out", str(site)]) == 0
    assert "[nbfc] unchanged" in capsys.readouterr().out

    src.write_text("Regn No,Company Name\n" + "".join(f"N-{i},Company {i}\n" for i in range(30)))  # 10 vanish
    assert run([str(sources), "--key", str(key), "--out", str(site)]) == 3
    assert "HELD" in capsys.readouterr().out and (site / "nbfc.json").read_bytes() == first

    src.write_text("Regn No,Company Name\n" + "".join(f"N-{i},Company {i}\n" for i in range(41)))  # one added
    assert run([str(sources), "--key", str(key), "--out", str(site)]) == 0
    assert "+1 -0" in capsys.readouterr().out


def test_a_broken_source_fails_without_stopping_the_others(tmp_path, capsys):
    src, sources, key, site = setup(tmp_path, range(5))
    src.write_text("no header here\n")
    assert load().main([str(sources), "--key", str(key), "--out", str(site)]) == 2
    assert "[nbfc] FAILED" in capsys.readouterr().out
