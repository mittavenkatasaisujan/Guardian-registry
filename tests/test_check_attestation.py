"""scripts/check_attestation.py reads chunked logcat evidence and checks it."""

import importlib.util
import json
from pathlib import Path

from .test_attestation import PKG, AndroidPhone, Pki

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check_attestation.py"


def load():
    spec = importlib.util.spec_from_file_location("check_attestation", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def logcat(doc, size=500):
    text = json.dumps(doc)
    parts = [text[i:i + size] for i in range(0, len(text), size)]
    return "\n".join(f"{i + 1}/{len(parts)}:{p}" for i, p in enumerate(parts)) + "\n"


def test_good_evidence(tmp_path, capsys):
    p = AndroidPhone(Pki())
    f = tmp_path / "logcat.txt"
    f.write_text("--------- beginning of main\n" + logcat({"challenge": "c1", "device_key": p.public,
                                                              "attestation": p.evidence("c1")}))
    assert load().main([str(f), "--expect-package", PKG]) == 0
    assert "ok: the real Keystore chain verifies" in capsys.readouterr().out


def test_wrong_package(tmp_path):
    p = AndroidPhone(Pki())
    f = tmp_path / "logcat.txt"
    f.write_text(logcat({"challenge": "c1", "device_key": p.public, "attestation": p.evidence("c1")}))
    assert load().main([str(f), "--expect-package", "com.other"]) == 1


def test_missing_chunk(tmp_path):
    import pytest
    p = AndroidPhone(Pki())
    lines = logcat({"challenge": "c", "device_key": p.public, "attestation": p.evidence("c")}).splitlines()
    f = tmp_path / "logcat.txt"
    f.write_text("\n".join(lines[:-1]))
    with pytest.raises(SystemExit, match="incomplete"):
        load().main([str(f)])
