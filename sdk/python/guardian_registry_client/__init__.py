"""Client for banks and payment apps integrating with Guardian Registry.

    from guardian_registry_client import Client

    gr = Client("https://registry.example.in", api_key="...",
                cert=("bank-client.pem", "bank-client-key.pem"), ca="registry-ca.pem")
    result = gr.check(mobile="+919876543210", txn_id="TXN-123", amount_paise=2_000_000, payee="shop@upi")
    if result.may_execute:
        ...move the money...
        gr.report_outcome(result.check_id, completed=True)
    elif result.waiting:
        # held for a guardian or a cooling-off: tell the customer, then either wait for the
        # signed webhook (preferred) or poll:
        result = gr.wait_for_decision(result.check_id, timeout=1800)

What it handles for you:
  * Safe retries. A check is idempotent on your txn_id, so on a timeout, connection error,
    429 (honouring Retry-After) or 502/503/504 the SAME request is sent again; you never get
    two checks for one payment. Other 4xx errors are raised at once.
  * Mutual TLS: pass your client certificate and key; the registry pins it.
  * Webhooks: verify_webhook() checks X-GR-Signature in constant time before you trust a body.
  * Amounts are integer paise, never floats.

Only needs httpx. Python 3.10+.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

import httpx

__version__ = "0.21.0"
WAITING = ("cooling_off", "pending_approval")
RETRY_STATUSES = (429, 502, 503, 504)


class GuardianRegistryError(Exception):
    def __init__(self, status: int, detail: str, body: dict | None = None):
        super().__init__(f"HTTP {status}: {detail}")
        self.status, self.detail, self.body = status, detail, body or {}


class WebhookError(Exception):
    pass


@dataclass
class CheckResult:
    """A payment check, as the registry sees it. `raw` has every field."""
    raw: dict = field(repr=False)

    @property
    def check_id(self) -> str | None:
        return self.raw.get("check_id")  # None when the customer isn't enrolled

    @property
    def enrolled(self) -> bool:
        return bool(self.raw.get("enrolled", True))

    @property
    def status(self) -> str:
        return self.raw.get("status") or ("allowed" if not self.enrolled else "")

    @property
    def may_execute(self) -> bool:
        """True: you may move the money now. Only this field decides that."""
        return bool(self.raw.get("may_execute"))

    @property
    def waiting(self) -> bool:
        """Held for a guardian or cooling off: don't move money yet, don't fail it either."""
        return self.status in WAITING

    @property
    def reasons(self) -> list[str]:
        return list(self.raw.get("reasons") or [])

    @property
    def release_at(self) -> str | None:
        return self.raw.get("release_at")

    @property
    def approval_expires_at(self) -> str | None:
        return self.raw.get("approval_expires_at")


class Client:
    def __init__(self, base_url: str, api_key: str, *, cert: tuple[str, str] | None = None,
                 ca: str | None = None, timeout: float = 10.0, retries: int = 3,
                 http: httpx.Client | None = None, sleep=time.sleep):
        self.base = base_url.rstrip("/")
        self.headers = {"X-Api-Key": api_key, "Accept": "application/json",
                        "User-Agent": f"guardian-registry-client-python/{__version__}"}
        self.retries, self.sleep = retries, sleep
        if http is not None:
            self.http = http
        else:
            verify = True
            if ca or cert:
                import ssl
                ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
                if cert:
                    ctx.load_cert_chain(*cert)
                verify = ctx
            self.http = httpx.Client(timeout=timeout, verify=verify)

    # ------------------------------------------------------------------ transport
    def _call(self, method: str, path: str, body: dict | None = None, retry: bool = True) -> dict:
        attempts = self.retries + 1 if retry else 1
        for attempt in range(attempts):
            try:
                r = self.http.request(method, self.base + path, json=body, headers=self.headers)
            except (httpx.TimeoutException, httpx.TransportError) as e:
                if attempt + 1 >= attempts:
                    raise GuardianRegistryError(0, f"network error: {e}") from None
                self.sleep(self._backoff(attempt))
                continue
            if r.status_code in RETRY_STATUSES and attempt + 1 < attempts:
                wait = self._backoff(attempt)
                if r.status_code == 429:
                    try:
                        wait = max(wait, float(r.headers.get("Retry-After", "1")))
                    except ValueError:
                        pass
                self.sleep(min(wait, 30))
                continue
            data = r.json() if r.content else {}
            if r.status_code >= 400:
                detail = data.get("detail") if isinstance(data, dict) else None
                raise GuardianRegistryError(r.status_code, str(detail or r.reason_phrase), data)
            return data
        raise GuardianRegistryError(0, "retries exhausted")  # pragma: no cover

    @staticmethod
    def _backoff(attempt: int) -> float:
        return min(0.5 * (2 ** attempt), 8.0)

    # ------------------------------------------------------------------ payments
    def check(self, mobile: str, txn_id: str, amount_paise: int, payee: str, channel: str = "upi") -> CheckResult:
        """Ask before moving money. Safe to call again with the same txn_id."""
        if not isinstance(amount_paise, int) or isinstance(amount_paise, bool) or amount_paise <= 0:
            raise ValueError("amount_paise must be a positive int (paise, not rupees)")
        return CheckResult(self._call("POST", "/v1/checks", {
            "mobile": mobile, "participant_txn_id": txn_id, "amount": amount_paise, "payee": payee,
            "channel": channel}))

    def get_check(self, check_id: str) -> CheckResult:
        return CheckResult(self._call("GET", f"/v1/checks/{check_id}"))

    def wait_for_decision(self, check_id: str, timeout: float = 1800, poll_every: float = 5.0) -> CheckResult:
        """Poll until the check leaves cooling-off / pending approval, or `timeout` seconds pass
        (then the still-waiting result is returned). Prefer the check.updated webhook."""
        deadline = time.monotonic() + timeout
        while True:
            res = self.get_check(check_id)
            if not res.waiting or time.monotonic() >= deadline:
                return res
            self.sleep(poll_every)

    def report_outcome(self, check_id: str, completed: bool) -> CheckResult:
        """After you executed (completed=True) or failed (False) a payment the registry let through.
        A failed payment frees the daily limit; a completed one makes the payee "known"."""
        try:
            return CheckResult(self._call("POST", f"/v1/checks/{check_id}/outcome", {"completed": completed}))
        except GuardianRegistryError as e:
            if e.status == 409 and "already reported" in e.detail:
                return self.get_check(check_id)  # a retry of a report that already arrived
            raise

    def label_fraud(self, check_id: str, fraud: bool, note: str | None = None) -> dict:
        """Once you know the outcome: confirmed fraud (True) or genuine (False). Labels tune the
        scam signals for every bank; they never change the check."""
        return self._call("POST", f"/v1/checks/{check_id}/fraud-label", {"fraud": fraud, "note": note})

    # ------------------------------------------------------------------ signals
    def report_sim_change(self, mobile: str, changed_at: str | None = None) -> dict:
        return self._call("POST", "/v1/signals/sim-change", {"mobile": mobile, "changed_at": changed_at})

    def report_fraud_payee(self, payee: str, reason: str, case_ref: str | None = None) -> dict:
        """After you CONFIRMED a fraud: protects every bank's customers from this payee."""
        return self._call("POST", "/v1/signals/fraud-payees", {"payee": payee, "reason": reason,
                                                               "evidence_ref": case_ref})

    def payee_status(self, payee: str) -> dict:
        from urllib.parse import quote
        return self._call("GET", f"/v1/signals/fraud-payees/{quote(payee, safe='@.')}")

    # ------------------------------------------------------------------ account
    def me(self) -> dict:
        return self._call("GET", "/v1/participant/me")

    def set_webhook(self, url: str) -> dict:
        """Returns the webhook secret (shown once): keep it to verify deliveries."""
        return self._call("PUT", "/v1/participant/webhook", {"url": url}, retry=False)


# ---------------------------------------------------------------------- webhooks
def verify_webhook(secret: str, body: bytes, signature: str | None) -> bool:
    """X-GR-Signature is 'sha256=' + hex HMAC-SHA256(secret, raw body). Check the RAW bytes,
    before parsing; compare in constant time."""
    if not signature or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def parse_webhook(secret: str, body: bytes, signature: str | None) -> dict:
    """Verified event: {"id", "event", "created_at", "data"}. De-duplicate on "id" (X-GR-Delivery):
    a delivery can arrive more than once."""
    if not verify_webhook(secret, body, signature):
        raise WebhookError("bad or missing X-GR-Signature")
    return json.loads(body)


__all__ = ["Client", "CheckResult", "GuardianRegistryError", "WebhookError", "verify_webhook", "parse_webhook"]
