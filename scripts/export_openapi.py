"""Write docs/openapi.json, the API description banks and app developers build against.

    python scripts/export_openapi.py

tests/test_bank_kit.py fails when the code's API and this file differ, so the published
description can't go stale: re-run this after changing an endpoint.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from guardian_registry.api import create_app  # noqa: E402
from guardian_registry.db import Database  # noqa: E402
from guardian_registry.service import Registry  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "docs" / "openapi.json"


def spec() -> str:
    app = create_app(Registry(Database(":memory:")), run_worker=False)
    return json.dumps(app.openapi(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


if __name__ == "__main__":
    OUT.write_text(spec(), encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(Path.cwd()) if Path.cwd() in OUT.parents else OUT}")
