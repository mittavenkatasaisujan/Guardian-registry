"""Local development server: fresh database, OTP codes echoed, one admin token.

    .venv\\Scripts\\python scripts\\dev_server.py [port]

Then open http://127.0.0.1:<port>/app/ . Never use these settings in production.
"""

import os
import sys
from pathlib import Path

args = [a for a in sys.argv[1:] if not a.startswith("--")]
port = int(args[0]) if args else 8010
# --lan: listen on every interface so a phone on the same Wi-Fi can reach this PC
# (allow the port through the firewall when asked). Development only.
host = "0.0.0.0" if "--lan" in sys.argv else "127.0.0.1"
db = Path(os.environ.get("GR_DB", "webdev.db"))
for suffix in ("", "-wal", "-shm"):
    Path(str(db) + suffix).unlink(missing_ok=True)

# --real: real SMS (Twilio trial) and push (Firebase) from local-secrets/real.env, which is
# git-ignored. Codes then arrive by SMS instead of being shown on screen. See docs/free-testing.md.
real = "--real" in sys.argv
if real:
    env_file = Path(__file__).resolve().parent.parent / "local-secrets" / "real.env"
    if not env_file.exists():
        sys.exit(f"--real needs {env_file} (see docs/free-testing.md)")
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            v = v.strip()
            if k.strip().endswith("_FILE") and not os.path.isabs(v):   # paths relative to the repository
                v = str(env_file.parent.parent / v)
            os.environ.setdefault(k.strip(), v)
    for k, v in os.environ.items():
        if k.endswith("_FILE") and k.startswith("GR_") and not os.path.exists(v):
            sys.exit(f"{k} points to {v}, which doesn't exist yet")

os.environ.setdefault("GR_DB", str(db))
os.environ.setdefault("GR_OTP_DEV_ECHO", "0" if real else "1")
os.environ.setdefault("GR_ADMIN_TOKEN", "dev-admin")
os.environ.setdefault("GR_WORKER_INTERVAL", "2")

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# `kill -USR1 <pid>` prints every thread's stack to stderr: for finding a stuck request
import faulthandler  # noqa: E402
import signal  # noqa: E402
if hasattr(signal, "SIGUSR1"):
    faulthandler.register(signal.SIGUSR1, all_threads=True)
import uvicorn  # noqa: E402

if host == "0.0.0.0":
    # Every real address of this PC: a VPN or virtual adapter can make "the" route-based guess
    # wrong, so list them all (link-local 169.254.x.x and loopback left out).
    import socket
    found = []
    try:
        found += socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        pass
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent
        route = s.getsockname()[0]
    except OSError:
        route = None
    finally:
        s.close()
    addrs = [a for a in dict.fromkeys(found) if not a.startswith(("127.", "169.254."))]
    if not addrs and route:   # only when the PC lists none: the route guess can name a VPN's address
        addrs = [route]
    print("Phone on the same Wi-Fi: use one of these as the server address:", flush=True)
    for a in addrs:
        print(f"    http://{a}:{port}", flush=True)
# keep idle connections longer than clients do, so a reused connection is never closed mid-request
uvicorn.run("guardian_registry.api:create_app", factory=True, host=host, port=port, timeout_keep_alive=75)
