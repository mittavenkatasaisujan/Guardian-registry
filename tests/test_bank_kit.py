"""The bank integration kit stays in step with the code."""

import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _export():
    spec = importlib.util.spec_from_file_location("export_openapi", ROOT / "scripts" / "export_openapi.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_published_openapi_matches_the_code():
    published = (ROOT / "docs" / "openapi.json").read_text(encoding="utf-8")
    assert published == _export().spec(), "the API changed: run  python scripts/export_openapi.py"


def test_bank_endpoints_are_documented():
    paths = json.loads((ROOT / "docs" / "openapi.json").read_text(encoding="utf-8"))["paths"]
    for p in ("/v1/checks", "/v1/checks/{check_id}", "/v1/checks/{check_id}/outcome", "/v1/participant/webhook",
              "/v1/signals/fraud-payees", "/v1/signals/sim-change"):
        assert p in paths, p
    guide = (ROOT / "docs" / "bank-integration.md").read_text(encoding="utf-8")
    for p in ("/v1/checks", "X-GR-Signature", "participant_txn_id", "may_execute", "bank_conformance.py"):
        assert p in guide, p


def test_library_versions_match_the_server():
    from guardian_registry import __version__
    py = (ROOT / "sdk" / "python" / "guardian_registry_client" / "__init__.py").read_text(encoding="utf-8")
    java = (ROOT / "sdk" / "java" / "build.gradle.kts").read_text(encoding="utf-8")
    assert f'__version__ = "{__version__}"' in py
    assert f'version = "{__version__}"' in java
