"""Local development server: fresh database, OTP codes echoed, one admin token.

    .venv\\Scripts\\python scripts\\dev_server.py [port]

Then open http://127.0.0.1:<port>/app/ . Never use these settings in production.
"""

import os
import sys
from pathlib import Path

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8010
db = Path(os.environ.get("GR_DB", "webdev.db"))
for suffix in ("", "-wal", "-shm"):
    Path(str(db) + suffix).unlink(missing_ok=True)

os.environ.setdefault("GR_DB", str(db))
os.environ.setdefault("GR_OTP_DEV_ECHO", "1")
os.environ.setdefault("GR_ADMIN_TOKEN", "dev-admin")
os.environ.setdefault("GR_WORKER_INTERVAL", "2")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# `kill -USR1 <pid>` prints every thread's stack to stderr: for finding a stuck request
import faulthandler  # noqa: E402
import signal  # noqa: E402
if hasattr(signal, "SIGUSR1"):
    faulthandler.register(signal.SIGUSR1, all_threads=True)
import uvicorn  # noqa: E402

# keep idle connections longer than clients do, so a reused connection is never closed mid-request
uvicorn.run("guardian_registry.api:create_app", factory=True, host="127.0.0.1", port=port, timeout_keep_alive=75)
