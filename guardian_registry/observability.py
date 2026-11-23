"""Metrics, request IDs and structured logs, with no extra dependencies.

  * GET /metrics      Prometheus text format. Protected by GR_METRICS_TOKEN (bearer); in
                      production it is off unless the token is set.
  * GET /readyz       200 only when the database answers and its schema is current, for load
                      balancers and Kubernetes readiness probes (/healthz stays a liveness check).
  * X-Request-ID      accepted from the proxy (if it looks sane) or generated, echoed on the
                      response, and attached to every log line of that request.
  * GR_LOG_FORMAT=json  one JSON object per log line (time, level, logger, message,
                      request_id), for log shippers. Phone numbers never reach the logs: the
                      code logs only masked numbers.

Request metrics use the route TEMPLATE (/v1/checks/{check_id}), never the raw path, so ids
don't explode the number of series. Business gauges (alerts waiting, failed deliveries,
feeds in error, held refreshes) are read from the shared database at scrape time, so every
node reports the same numbers and nothing is lost on restart.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import secrets
import threading
import time

request_id: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
_RID_OK = re.compile(r"^[A-Za-z0-9._:-]{8,100}$")


def clean_request_id(value: str | None) -> str:
    return value if value and _RID_OK.match(value) else secrets.token_hex(12)


def _labels(d: dict) -> str:
    if not d:
        return ""
    esc = {k: str(v).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") for k, v in d.items()}
    return "{" + ",".join(f'{k}="{v}"' for k, v in sorted(esc.items())) + "}"


class Metrics:
    def __init__(self):
        self._lock = threading.Lock()
        self.counters: dict[tuple[str, tuple], float] = {}
        self.hist: dict[tuple[str, tuple], list] = {}  # [bucket counts..., sum, count]
        self.help: dict[str, tuple[str, str]] = {}

    def describe(self, name: str, kind: str, text: str) -> None:
        self.help[name] = (kind, text)

    def inc(self, name: str, labels: dict | None = None, by: float = 1) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self.counters[key] = self.counters.get(key, 0) + by

    def observe(self, name: str, value: float, labels: dict | None = None) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            h = self.hist.setdefault(key, [0] * len(BUCKETS) + [0.0, 0])
            for i, b in enumerate(BUCKETS):
                if value <= b:
                    h[i] += 1
            h[-2] += value
            h[-1] += 1

    def render(self, gauges: dict[str, list[tuple[dict, float]]] | None = None) -> str:
        out: list[str] = []
        seen: set[str] = set()

        def head(name):
            if name not in seen and name in self.help:
                kind, text = self.help[name]
                out.append(f"# HELP {name} {text}")
                out.append(f"# TYPE {name} {kind}")
            seen.add(name)

        with self._lock:
            for (name, labels), v in sorted(self.counters.items()):
                head(name)
                out.append(f"{name}{_labels(dict(labels))} {v:g}")
            for (name, labels), h in sorted(self.hist.items()):
                head(name)
                lab = dict(labels)
                for i, b in enumerate(BUCKETS):
                    out.append(f"{name}_bucket{_labels({**lab, 'le': f'{b:g}'})} {h[i]}")
                out.append(f"{name}_bucket{_labels({**lab, 'le': '+Inf'})} {h[-1]}")
                out.append(f"{name}_sum{_labels(lab)} {h[-2]:.6f}")
                out.append(f"{name}_count{_labels(lab)} {h[-1]}")
        for name, samples in (gauges or {}).items():
            head(name)
            for lab, v in samples:
                out.append(f"{name}{_labels(lab)} {v:g}")
        return "\n".join(out) + "\n"


def new_metrics() -> Metrics:
    m = Metrics()
    m.describe("gr_http_requests_total", "counter", "HTTP requests by method, route template and status")
    m.describe("gr_http_request_seconds", "histogram", "HTTP request latency by route template")
    m.describe("gr_checks_total", "counter", "payment checks by decision status")
    m.describe("gr_worker_iterations_total", "counter", "background worker iterations, by outcome")
    m.describe("gr_notifications", "gauge", "alerts and webhooks in the outbox, by channel and status")
    m.describe("gr_register_feeds", "gauge", "register feeds by state (ok, error, held, pending)")
    m.describe("gr_up", "gauge", "1 if this node can reach its database")
    m.describe("gr_build_info", "gauge", "version of this node")
    return m


def business_gauges(db, version: str) -> dict:
    g: dict[str, list] = {"gr_build_info": [({"version": version}, 1)]}
    try:
        rows = db.all("SELECT channel, status, COUNT(*) n FROM notifications "
                      "WHERE status IN ('pending','failed') GROUP BY channel, status")
        g["gr_notifications"] = [({"channel": r["channel"], "status": r["status"]}, r["n"]) for r in rows]
        feeds = db.all("SELECT status, last_error, held_json FROM register_feeds")
        state = {"ok": 0, "error": 0, "held": 0, "pending": 0}
        for f in feeds:
            if f["status"] == "pending":
                state["pending"] += 1
            elif f["held_json"]:
                state["held"] += 1
            elif f["last_error"]:
                state["error"] += 1
            else:
                state["ok"] += 1
        g["gr_register_feeds"] = [({"state": k}, v) for k, v in state.items()]
        g["gr_up"] = [({}, 1)]
    except Exception:  # noqa: BLE001 - the scrape itself must still answer
        g["gr_up"] = [({}, 0)]
    return g


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        doc = {"time": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
               "level": record.levelname.lower(), "logger": record.name, "message": record.getMessage(),
               "request_id": request_id.get()}
        if record.exc_info:
            doc["exception"] = self.formatException(record.exc_info)
        return json.dumps(doc, ensure_ascii=False)


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id.get()
        return True
