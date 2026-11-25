"""HTTP API.

Three kinds of caller:
  * Banks / payment apps ("participants") send `X-Api-Key` and call /v1/checks.
  * People (principals and guardians) sign in with an SMS one-time code and then send
    `Authorization: Bearer <token>`.
  * Operators send `X-Admin-Token` to onboard and supervise participants. Configure named
    operators with GR_OPERATORS="alice:<token>,bob:<token>" (four-eyes: one registers,
    another approves). GR_ADMIN_TOKEN alone gives a single operator "admin", allowed only
    outside production, where it approves its own requests.

Run:  uvicorn guardian_registry.api:create_app --factory --port 8000
"""

import hmac
import logging
import math
import os
from pathlib import Path
import secrets
import threading
import time
from contextlib import asynccontextmanager
from typing import Annotated, Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, messages
from .db import Database
from .errors import RegistryError
from .models import CHANNELS, KINDS
from .notify import Dispatcher, PushSender, SmsSender, WhatsAppSender, sms_sender_from_env
from .participants import CAPABILITIES, PARTICIPANT_KINDS
from .certs import ProxyTrust
from .devicekeys import KeyAttestor, key_attestor_from_env
from .simfeed import SimLookup, sim_lookup_from_env
from .presets import PRESETS
from .operator_auth import OidcVerifier, OperatorAuthError, oidc_from_env
from .ratelimit import RateLimiter, make_limiter
from .security import check_production_config, is_production
from .service import OTP_TTL_MINUTES, Registry

log = logging.getLogger("guardian_registry.api")

WEB_DIR = Path(__file__).parent / "web"
APP_CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
           "manifest-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


# ----------------------------------------------------------------- schemas
class OtpIn(BaseModel):
    mobile: str
    language: str | None = Field(default=None, max_length=10, description="language of the code SMS (e.g. hi, ta)")


class LanguageIn(BaseModel):
    language: str = Field(min_length=2, max_length=10, description="one of GET /v1/languages")


class VerifyIn(BaseModel):
    mobile: str
    code: str = Field(min_length=4, max_length=10)
    display_name: str | None = Field(default=None, max_length=80)
    adult: bool = Field(default=False, description="creating an account: the person confirms they are 18 or older "
                                                  "(required; refused with code adult_required otherwise)")
    language: str | None = Field(default=None, max_length=10,
                                 description="the app's language (e.g. hi-IN); used for alerts and SMS if enabled")
    device_id: str | None = Field(default=None, max_length=200,
                                  description="stable app-install id; new devices start on probation")
    device_key: str | None = Field(default=None, max_length=400,
                                   description="base64 DER public key (EC P-256) kept in secure hardware")
    challenge: str | None = Field(default=None, max_length=200, description="from POST /v1/auth/challenge")
    device_proof: str | None = Field(default=None, max_length=400,
                                     description="base64 ECDSA-SHA256 signature of 'guardian-registry/v1:'+challenge")
    key_attestation: str | None = Field(default=None, max_length=20000,
                                        description="JSON: Android Key Attestation chain or Apple App Attest object (see attestation.py)")
    platform: Literal["android", "ios", "web"] | None = None


class SimChangeIn(BaseModel):
    mobile: str
    changed_at: str | None = Field(default=None, description="ISO 8601 with timezone; default now")


class OperatorEvent(BaseModel):
    event_id: str = Field(min_length=1, max_length=100, description="your id; resending it is a no-op")
    type: Literal["sim_swap", "port_out", "disconnected"]
    mobile: str
    occurred_at: str = Field(description="ISO 8601 with timezone")


class OperatorEventsIn(BaseModel):
    events: list[OperatorEvent] = Field(min_length=1, max_length=500)


class NewMobileIn(BaseModel):
    new_mobile: str


class NewMobileVerifyIn(BaseModel):
    new_mobile: str
    code: str = Field(min_length=4, max_length=10)


class RecoveryStartIn(BaseModel):
    old_mobile: str = Field(description="the number that was disconnected")
    new_mobile: str
    code: str = Field(min_length=4, max_length=10, description="code sent to new_mobile by /v1/auth/otp")


class RecoveryTokenIn(BaseModel):
    recovery_token: str = Field(min_length=8, max_length=200)


class BankRecoveryIn(BaseModel):
    new_mobile: str
    customer_ref: str = Field(min_length=1, max_length=100, description="the id you used when you attested before")
    assisted: bool = Field(default=False, description="in-person recovery for someone with no contacts and no "
                                                      "earlier KYC; needs verified_on; held 7 days")
    verified_on: str | None = None
    date_of_birth: str | None = None


class LogoutIn(BaseModel):
    everywhere: bool = False


class ParticipantIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: Literal[tuple(PARTICIPANT_KINDS)] = "bank"  # type: ignore[valid-type]
    regulator_ref: str = Field(min_length=3, max_length=60,
                               description="licence / registration number, e.g. RBI or NPCI reference")
    capabilities: list[Literal[CAPABILITIES]] | None = Field(  # type: ignore[valid-type]
        default=None, description="default: the usual set for this kind")


class EntityIn(BaseModel):
    regulator_ref: str = Field(min_length=1, max_length=60)
    name: str = Field(min_length=1, max_length=200)


class RegisterIn(BaseModel):
    source: str = Field(min_length=3, max_length=300, description="where the list came from, e.g. its URL")
    as_of: str = Field(min_length=4, max_length=40, description="date of the published list")
    entities: list[EntityIn] = Field(min_length=1, max_length=20000)


class FraudPayeeIn(BaseModel):
    payee: str = Field(min_length=1, max_length=200, description="UPI ID or account reference the money went to")
    reason: str = Field(min_length=5, max_length=500, description="what happened, in a sentence")
    evidence_ref: str | None = Field(default=None, max_length=100, description="your case or complaint number")


class FraudLabelIn(BaseModel):
    fraud: bool = Field(description="true: confirmed fraud; false: confirmed genuine")
    note: str | None = Field(default=None, max_length=200)


class SignalSettingsIn(BaseModel):
    model_config = {"extra": "forbid"}
    large_multiple: float | None = None
    large_min: int | None = Field(default=None, description="paise")
    min_prior: int | None = None
    burst_count: int | None = None
    night_start: int | None = None
    night_end: int | None = None
    reason: str = Field(min_length=5, max_length=500, description="why: e.g. which tuning report this follows")


class IncidentIn(BaseModel):
    title: str = Field(min_length=5, max_length=200)
    description: str = Field(min_length=10, max_length=5000, description="what happened, as far as known")
    detected_at: str
    occurred_from: str
    occurred_to: str
    categories: list[Literal["mobile_numbers", "names", "dates_of_birth", "payment_history", "sign_in_sessions",
                             "device_data"]] = Field(min_length=1)
    cause: str = Field(default="", max_length=5000)
    containment: str = Field(default="", max_length=5000)
    scope: Literal["window", "all", "users"] = "window"
    user_ids: list[str] | None = Field(default=None, max_length=100000)


class IncidentUpdateIn(BaseModel):
    cause: str | None = Field(default=None, max_length=5000)
    containment: str | None = Field(default=None, max_length=5000)
    remediation: str | None = Field(default=None, max_length=5000)


class BoardReportIn(BaseModel):
    reference: str = Field(min_length=1, max_length=100, description="the Board's acknowledgement number")


class WatchDecisionIn(BaseModel):
    reason: str = Field(min_length=5, max_length=500)


class ConsentIn(BaseModel):
    notice_version: str = Field(min_length=4, max_length=40, description="the version from GET /v1/privacy/notice")


class FeedIn(BaseModel):
    url: str = Field(min_length=8, max_length=500, description="https URL of the published list")
    format: Literal["csv", "xlsx", "json"] = "csv"
    sheet: str | None = Field(default=None, max_length=100, description="xlsx: worksheet name (default: the first)")
    ref_field: str = Field(default="regulator_ref", min_length=1, max_length=200,
                           description="header of the licence-number column; alternatives with '|'")
    name_field: str = Field(default="name", min_length=1, max_length=200,
                            description="header of the name column; alternatives with '|'")
    public_key: str | None = Field(default=None, max_length=100,
                                   description="Ed25519 key (base64); the list must then be signed at <url>.sig")
    max_drop_pct: int = Field(default=5, ge=0, le=100)
    auto_suspend: bool = True


class CertIn(BaseModel):
    certificate: str = Field(min_length=50, max_length=20000, description="PEM client certificate")


class ReasonIn(BaseModel):
    reason: str = Field(min_length=3, max_length=300)


class CapabilitiesIn(BaseModel):
    capabilities: list[Literal[CAPABILITIES]]  # type: ignore[valid-type]


class WebhookIn(BaseModel):
    url: str | None = Field(default=None, max_length=500)


class InviteIn(BaseModel):
    mobile: str


class QuietHoursIn(BaseModel):
    """Chosen channels switched off every day between two hours, India time (end may be next day)."""
    model_config = {"extra": "forbid"}
    channels: list[str] = Field(min_length=1, description="e.g. [\"upi\"]")
    start: int = Field(ge=0, le=23, description="hour it starts, e.g. 22")
    end: int = Field(ge=0, le=23, description="hour it ends, e.g. 6")


class RulesPatch(BaseModel):
    """Only the fields you send are changed. Amounts are in paise; null means no limit."""
    model_config = {"extra": "forbid"}
    per_txn_limit: int | None = None
    daily_limit: int | None = None
    approval_threshold: int | None = None
    new_payee_delay_threshold: int | None = None
    cooling_off_minutes: int | None = None
    approval_timeout_minutes: int | None = None
    blocked_channels: list[str] | None = None
    require_verified_guardian: bool | None = None
    scam_signals: bool | None = None
    per_payee_daily_limit: int | None = None
    channel_daily_limits: dict[str, int] | None = None
    approval_scope: Literal["all", "rbi"] | None = None
    new_guardian_wait_hours: int | None = None
    quiet_hours: QuietHoursIn | None = None


class NameIn(BaseModel):
    display_name: str = Field(min_length=1, max_length=80)


class NomineeIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    relation: str = Field(min_length=1, max_length=40, description="e.g. son, daughter, spouse")
    mobile: str


class AttestIn(BaseModel):
    """A bank vouches that it has KYC'd this registry user. The customer must approve it."""
    mobile: str
    kyc_level: Literal["full", "minimum"]
    customer_ref: str = Field(min_length=1, max_length=100, description="your own customer id; stored only hashed")
    verified_on: str = Field(description="date KYC was completed, YYYY-MM-DD")
    date_of_birth: str | None = Field(default=None, description="optional, YYYY-MM-DD; only a senior yes/no is shared")


class PayeeIn(BaseModel):
    payee: str = Field(min_length=1, max_length=200)


class AlertChannelIn(BaseModel):
    urgent_channel: Literal["sms", "whatsapp"]


class PushTokenIn(BaseModel):
    token: str = Field(min_length=8, max_length=4096, description="FCM / APNs device token")
    platform: Literal["android", "ios", "web"]


class ReadIn(BaseModel):
    ids: list[str] | None = None


class CheckIn(BaseModel):
    mobile: str
    participant_txn_id: str = Field(min_length=1, max_length=100)
    amount: int = Field(description="paise")
    payee: str = Field(min_length=1, max_length=200)
    channel: Literal[CHANNELS] = "upi"  # type: ignore[valid-type]
    kind: Literal[KINDS] = Field(  # type: ignore[valid-type]
        default="transfer",
        description="transfer, merchant (a payment to a shop), recurring (a debit under an existing mandate or "
                    "standing instruction) or new_mandate. Existing recurring mandates still run while payments are "
                    "paused, and with approval_scope 'rbi' only transfers outside UPI go to the trusted person.")
    narration: str | None = Field(default=None, max_length=140,
                                  description="the payment's note as the customer typed it; guardians see it "
                                              "when they approve (RBI's draft trusted person mechanism)")


class OutcomeIn(BaseModel):
    completed: bool


# ------------------------------------------------------------------ worker
class Worker(threading.Thread):
    """Background loop: move time-based state forward, then deliver alerts and webhooks."""

    def __init__(self, registry: Registry, dispatcher: Dispatcher, interval: float, metrics=None):
        super().__init__(name="guardian-registry-worker", daemon=True)
        self.registry, self.dispatcher, self.interval = registry, dispatcher, interval
        self.metrics = metrics
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.is_set():
            outcome = "ok"
            try:
                self.registry.sweep()
                self.dispatcher.run_once()
            except Exception:  # noqa: BLE001 - keep the loop alive, log and continue
                outcome = "error"
                log.exception("worker iteration failed")
            if self.metrics:
                self.metrics.inc("gr_worker_iterations_total", {"outcome": outcome})
            self.stop_event.wait(self.interval)

    def stop(self) -> None:
        self.stop_event.set()


def parse_operators(spec: str | None) -> dict[str, str]:
    """'alice:tok1,bob:tok2' -> {'alice': 'tok1', 'bob': 'tok2'}."""
    ops: dict[str, str] = {}
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        name, sep, token = part.partition(":")
        name, token = name.strip(), token.strip()
        if not sep or not name or not token:
            raise RuntimeError("GR_OPERATORS must look like 'alice:<token>,bob:<token>'")
        if name in ops or token in ops.values():
            raise RuntimeError("GR_OPERATORS names and tokens must be unique")
        if len(token) < 16 and is_production():
            raise RuntimeError(f"operator token for {name!r} is too short (16+ characters)")
        ops[name] = token
    return ops


def create_app(
    registry: Registry | None = None,
    admin_token: str | None = None,
    *,
    operators: dict[str, str] | None = None,
    sim_lookup: SimLookup | None = None,
    key_attestor: KeyAttestor | None = None,
    proxy_trust: ProxyTrust | None = None,
    operator_sso: OidcVerifier | None = None,
    sms: SmsSender | None = None,
    whatsapp: WhatsAppSender | None = None,
    push: PushSender | None = None,
    http: httpx.Client | None = None,
    run_worker: bool | None = None,
    check_rate: str | None = None,
    otp_rate: str | None = None,
) -> FastAPI:
    check_production_config()
    from .observability import JsonFormatter, RequestIdFilter, business_gauges, new_metrics
    pkg_log = logging.getLogger("guardian_registry")
    if not pkg_log.handlers:  # make dev SMS / worker messages visible next to uvicorn's own logs
        handler = logging.StreamHandler()
        if os.environ.get("GR_LOG_FORMAT", "text") == "json":
            handler.setFormatter(JsonFormatter())
        else:
            handler.setFormatter(logging.Formatter("%(levelname)s:     %(name)s [%(request_id)s]: %(message)s"))
        handler.addFilter(RequestIdFilter())
        pkg_log.addHandler(handler)
        pkg_log.setLevel(logging.INFO)
    metrics = new_metrics()
    metrics_token = os.environ.get("GR_METRICS_TOKEN")
    from .secrets_store import load_secret_files
    load_secret_files()  # GR_X_FILE -> GR_X, before anything reads a secret
    reg = registry or Registry(Database(os.environ.get("GR_DB", "guardian_registry.db")))
    if sim_lookup is not None:
        reg.sim_lookup = sim_lookup
    elif reg.sim_lookup is None:
        reg.sim_lookup = sim_lookup_from_env()
    if key_attestor is not None:
        reg.key_attestor = key_attestor
    elif reg.key_attestor is None:
        reg.key_attestor = key_attestor_from_env(reg.clock)
    if operators is None:
        operators = parse_operators(os.environ.get("GR_OPERATORS"))
        admin = admin_token if admin_token is not None else os.environ.get("GR_ADMIN_TOKEN")
        if admin and not operators:
            operators = {"admin": admin}
    operators = {k: v for k, v in operators.items() if v}
    sso = operator_sso if operator_sso is not None else oidc_from_env()
    n_operators = len(operators) + (len(sso.allowed) if sso else 0)
    if is_production() and n_operators == 1:
        raise RuntimeError("unsafe production config: configure at least two operators (GR_OPERATORS or "
                           "GR_OPERATOR_OIDC_ALLOWED); participant onboarding needs a second approver")
    single_operator = n_operators == 1  # dev convenience: approves its own requests
    sms = sms or sms_sender_from_env()
    if getattr(sms, "checks_codes", False):   # Twilio Verify: every node can check codes
        reg.code_checker = sms
    dispatcher = Dispatcher(reg.db, reg.clock, sms=sms, http=http, whatsapp=whatsapp, push=push)
    if run_worker is None:
        run_worker = os.environ.get("GR_WORKER", "1") == "1"
    worker_interval = float(os.environ.get("GR_WORKER_INTERVAL", "5"))
    rate_backend = os.environ.get("GR_RATE_BACKEND", "memory")
    check_limiter = make_limiter(reg.db, "checks", check_rate or os.environ.get("GR_RATE_CHECKS", "600/60"),
                                 rate_backend)
    otp_limiter = make_limiter(reg.db, "otp", otp_rate or os.environ.get("GR_RATE_OTP", "10/60"), rate_backend)
    dev_echo = os.environ.get("GR_OTP_DEV_ECHO") == "1" and not is_production()
    proxies = proxy_trust or ProxyTrust()

    def client_ip(request: Request) -> str:
        """Rate-limit key: the real client behind our trusted proxies (see ProxyTrust.client_ip)."""
        return proxies.client_ip(request.client.host if request.client else None, request.headers)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        worker = Worker(reg, dispatcher, worker_interval, metrics) if run_worker else None
        if worker:
            worker.start()
        try:
            yield
        finally:
            if worker:
                worker.stop()
                worker.join(timeout=worker_interval + 1)

    app = FastAPI(title="Guardian Registry", version=__version__, lifespan=lifespan,
                  description="Cross-bank trusted-person and payment-protection registry.")
    app.state.registry = reg
    app.state.dispatcher = dispatcher
    app.state.metrics = metrics

    from .observability import EdgeMiddleware
    app.add_middleware(EdgeMiddleware, metrics=metrics, app_csp=APP_CSP)

    @app.exception_handler(RegistryError)
    async def _registry_error(request: Request, exc: RegistryError):
        lang = messages.language_from_header(request.headers.get("accept-language"))
        body = {"error": type(exc).__name__, "detail": messages.error(str(exc), lang)}
        if exc.code:
            body["code"] = exc.code   # stable whatever the language of `detail`
        return JSONResponse(status_code=exc.status, content=body)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException):
        lang = messages.language_from_header(request.headers.get("accept-language"))
        body = dict(exc.detail) if isinstance(exc.detail, dict) else {"detail": exc.detail}
        if isinstance(body.get("detail"), str):
            body["detail"] = messages.error(body["detail"], lang)
        return JSONResponse(status_code=exc.status_code, content=body, headers=getattr(exc, "headers", None))

    def limited(limiter, key: str) -> None:
        ok, retry = limiter.hit(key)
        if not ok:
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(math.ceil(retry) or 1)})

    # ------------------------------------------------------------- auth deps
    def participant(request: Request, x_api_key: Annotated[str | None, Header()] = None) -> str:
        pid = reg.participant_by_key(x_api_key) if x_api_key else None
        if not pid:
            raise HTTPException(401, "missing or invalid X-Api-Key")
        forwarded = proxies.certificate(request.client.host if request.client else None, request.headers)
        try:
            request.state.client_cert = reg.check_client_cert(pid, forwarded)  # mutual TLS (certs.py)
        except RegistryError as e:
            raise HTTPException(401, str(e)) from None
        return pid

    def bearer_token(authorization: Annotated[str | None, Header()] = None) -> str | None:
        return authorization[7:] if authorization and authorization.lower().startswith("bearer ") else None

    def session(token: Annotated[str | None, Depends(bearer_token)]) -> dict:
        info = reg.session_info(token) if token else None
        if not info:
            raise HTTPException(401, "missing, invalid or expired bearer token")
        return info

    def user(info: Annotated[dict, Depends(session)]) -> str:
        return info["user_id"]

    def restricted_error(info: dict) -> HTTPException:
        return HTTPException(403, {
            "error": "RestrictedSession",
            "detail": "this sign-in can't do that yet: " + "; ".join(info["reasons"]),
            "reasons": info["reasons"],
            "allowed": ["read", "deny", "cancel", "veto", "kill switch on", "tighten rules", "report lost phone"],
        })

    def trusted_user(info: Annotated[dict, Depends(session)],
                     token: Annotated[str | None, Depends(bearer_token)]) -> str:
        """For actions a phone-number thief must not be able to take (see simswap.py).
        First asks the mobile operator (cached) whether the SIM just changed."""
        if not info["restricted"]:
            if reg.lookup_blocks_trust(info["user_id"]):
                raise restricted_error({**info, "reasons": [
                    "we couldn't confirm with your mobile operator that your SIM hasn't changed; try again shortly"]})
            info = reg.session_info(token) or info
        if info["restricted"]:
            raise restricted_error(info)
        return info["user_id"]

    def operator(x_admin_token: Annotated[str | None, Header()] = None,
                 authorization: Annotated[str | None, Header()] = None) -> str:
        if not operators and not sso:
            raise HTTPException(503, "admin API disabled: set GR_OPERATOR_OIDC_* or GR_OPERATORS "
                                     "(or GR_ADMIN_TOKEN in development)")
        if sso and authorization and authorization.lower().startswith("bearer "):
            try:
                return sso.verify(authorization[7:])
            except OperatorAuthError as e:
                raise HTTPException(401, str(e)) from None
        if not operators:
            raise HTTPException(401, "sign in with your identity provider: Authorization: Bearer <ID token>")
        found = None
        for name, token in operators.items():  # compare every token so timing reveals nothing
            if x_admin_token and secrets.compare_digest(x_admin_token.encode(), token.encode()):
                found = name
        if not found:
            raise HTTPException(401, "invalid X-Admin-Token")
        return found

    Participant = Annotated[str, Depends(participant)]
    User = Annotated[str, Depends(user)]
    TrustedUser = Annotated[str, Depends(trusted_user)]
    Session = Annotated[dict, Depends(session)]
    Operator = Annotated[str, Depends(operator)]

    # ------------------------------------------------------------------ web app
    if WEB_DIR.is_dir():
        app.mount("/app", StaticFiles(directory=WEB_DIR, html=True), name="app")

        @app.get("/", include_in_schema=False)
        def home():
            return RedirectResponse("/app/")

    # ------------------------------------------------------------------ ops
    @app.get("/healthz", tags=["ops"])
    def healthz():
        return {"ok": True, "version": __version__}

    @app.get("/readyz", tags=["ops"])
    def readyz():
        """Ready for traffic: the database answers and its schema is the one this code expects."""
        from .db import MIGRATIONS
        try:
            version = reg.db.schema_version()
        except Exception as e:  # noqa: BLE001
            return JSONResponse(status_code=503, content={"ready": False, "reason": f"database: {type(e).__name__}"})
        if version != len(MIGRATIONS):
            return JSONResponse(status_code=503, content={"ready": False,
                                                          "reason": f"schema v{version}, code expects v{len(MIGRATIONS)}"})
        return {"ready": True, "schema": version}

    @app.get("/metrics", include_in_schema=False)
    def prometheus(authorization: Annotated[str | None, Header()] = None):
        if metrics_token:
            if not authorization or not hmac.compare_digest(authorization, f"Bearer {metrics_token}"):
                raise HTTPException(401, "metrics need Authorization: Bearer <GR_METRICS_TOKEN>")
        elif is_production():
            raise HTTPException(404, "set GR_METRICS_TOKEN to enable /metrics in production")
        return PlainTextResponse(metrics.render(business_gauges(reg.db, __version__)),
                                 media_type="text/plain; version=0.0.4")

    @app.post("/v1/admin/participants", status_code=201, tags=["ops"])
    def add_participant(body: ParticipantIn, op: Operator):
        """Register a participant. It starts `pending` until a second operator approves it
        (with a single development operator it is approved at once)."""
        pid, key = reg.register_participant(body.name, body.kind, body.regulator_ref, body.capabilities,
                                            operator=op, activate=False)
        view = reg.participant_view(pid)
        if single_operator:
            view = reg.approve_participant_request(op, pid, allow_self=True)
        return {**view, "api_key": key, "note": "store the key now; it is not shown again"}

    @app.get("/v1/admin/participants/{participant_id}/certificates", tags=["ops"])
    def admin_certs(participant_id: str, _: Operator):
        return reg.participant_certs(participant_id)

    @app.post("/v1/admin/participants/{participant_id}/certificates", status_code=201, tags=["ops"])
    def admin_pin_cert(participant_id: str, body: CertIn, op: Operator):
        """Pin a client certificate. Pending until a second operator approves."""
        out = reg.request_cert_pin(op, participant_id, body.certificate)
        if single_operator:
            out = reg.approve_cert_pin(op, participant_id, out["fingerprint"], allow_self=True)
        return out

    @app.post("/v1/admin/participants/{participant_id}/certificates/{fingerprint}/approve", tags=["ops"])
    def admin_approve_cert(participant_id: str, fingerprint: str, op: Operator):
        return reg.approve_cert_pin(op, participant_id, fingerprint, allow_self=single_operator)

    @app.delete("/v1/admin/participants/{participant_id}/certificates/{fingerprint}", tags=["ops"])
    def admin_remove_cert(participant_id: str, fingerprint: str, op: Operator):
        return reg.remove_cert_pin(f"operator:{op}", participant_id, fingerprint)

    @app.put("/v1/admin/register/{kind}", tags=["ops"])
    def load_register(kind: str, body: RegisterIn, op: Operator):
        """Replace the official register for one kind (RBI / NPCI / DoT published list)."""
        return reg.load_regulated_entities(op, kind, body.source, body.as_of,
                                           [e.model_dump() for e in body.entities])

    @app.post("/v1/admin/data-key/rotate", tags=["ops"])
    def rotate_data_key(_: Operator, limit: int = 1000):
        """Re-encrypt stored secrets under the first key in GR_DATA_KEY. Repeat until
        remaining is 0, then remove the old key from GR_DATA_KEY."""
        from .secrets_store import rotate_data_key as rotate
        return rotate(reg.db, min(max(limit, 1), 10000))

    @app.get("/v1/admin/signals/report", tags=["ops"])
    def signals_report(_: Operator, days: int = 90, max_hold_rate: float = 0.05):
        """How well each scam signal predicts confirmed fraud, what other thresholds would do,
        suggestions within a hold-rate budget, and the registry's impact."""
        return reg.tuning_report(min(max(days, 1), 365), min(max(max_hold_rate, 0.001), 0.5))

    @app.get("/v1/admin/signals/settings", tags=["ops"])
    def signals_settings(_: Operator):
        return reg.signal_settings_view()

    @app.put("/v1/admin/signals/settings", tags=["ops"])
    def propose_signals(body: SignalSettingsIn, op: Operator):
        """Propose new thresholds; a second operator approves them."""
        changes = body.model_dump(exclude_none=True)
        reason = changes.pop("reason")
        out = reg.propose_signal_settings(op, changes, reason)
        if single_operator:
            out = reg.decide_signal_settings(op, True, allow_self=True)
        return out

    @app.post("/v1/admin/signals/settings/approve", tags=["ops"])
    def approve_signals(op: Operator):
        return reg.decide_signal_settings(op, True, allow_self=single_operator)

    @app.post("/v1/admin/signals/settings/reject", tags=["ops"])
    def reject_signals(op: Operator):
        return reg.decide_signal_settings(op, False)

    @app.post("/v1/admin/checks/{check_id}/fraud-label", tags=["ops"])
    def admin_label(check_id: str, body: FraudLabelIn, op: Operator):
        return reg.label_check(f"operator:{op}", check_id, body.fraud, body.note)

    @app.get("/v1/admin/incidents", tags=["ops"])
    def list_incidents(_: Operator):
        return reg.incidents()

    @app.post("/v1/admin/incidents", status_code=201, tags=["ops"])
    def record_incident(body: IncidentIn, op: Operator):
        """Record a personal-data breach (DPDP Act): what, when, which data, who is affected."""
        return reg.record_incident(op, body.title, body.description, body.detected_at, body.occurred_from,
                                   body.occurred_to, body.categories, body.cause, body.containment, body.scope,
                                   body.user_ids)

    @app.patch("/v1/admin/incidents/{incident_id}", tags=["ops"])
    def update_incident(incident_id: str, body: IncidentUpdateIn, op: Operator):
        return reg.update_incident(op, incident_id, body.cause, body.containment, body.remediation)

    @app.post("/v1/admin/incidents/{incident_id}/notify", tags=["ops"])
    def propose_notify(incident_id: str, op: Operator):
        """Propose telling every affected person; a second operator sends it."""
        out = reg.propose_notification(op, incident_id)
        if single_operator:
            out = reg.send_notification(op, incident_id, allow_self=True)
        return out

    @app.post("/v1/admin/incidents/{incident_id}/notify/approve", tags=["ops"])
    def approve_notify(incident_id: str, op: Operator):
        return reg.send_notification(op, incident_id, allow_self=single_operator)

    @app.get("/v1/admin/incidents/{incident_id}/board-report", tags=["ops"])
    def board_report(incident_id: str, _: Operator):
        """Everything the Data Protection Board's detailed report needs, and its 72-hour deadline."""
        return reg.board_report(incident_id)

    @app.post("/v1/admin/incidents/{incident_id}/board-report", tags=["ops"])
    def record_board_report(incident_id: str, body: BoardReportIn, op: Operator):
        return reg.record_board_report(op, incident_id, body.reference)

    @app.get("/v1/admin/watchlist", tags=["ops"])
    def admin_watchlist(_: Operator):
        """Payees banks have reported for fraud, with the reports and any operator decision."""
        return reg.watchlist()

    @app.post("/v1/admin/watchlist/{payee}/confirm", tags=["ops"])
    def admin_watch_confirm(payee: str, body: WatchDecisionIn, op: Operator):
        """Confirm fraud on one bank's report: payments to the payee are then blocked."""
        return reg.operator_watch_decision(op, payee, "confirmed", body.reason)

    @app.post("/v1/admin/watchlist/{payee}/clear", tags=["ops"])
    def admin_watch_clear(payee: str, body: WatchDecisionIn, op: Operator):
        """Clear a payee reported by mistake: reports made before now stop counting."""
        return reg.operator_watch_decision(op, payee, "cleared", body.reason)

    @app.get("/v1/admin/register", tags=["ops"])
    def register_status(_: Operator):
        return reg.register_status()

    @app.get("/v1/admin/register-feeds", tags=["ops"])
    def list_feeds(_: Operator):
        return reg.feeds()

    @app.put("/v1/admin/register-feeds/{kind}", tags=["ops"])
    def configure_feed(kind: str, body: FeedIn, op: Operator):
        """Point a kind at a published list. A second operator must approve it; the worker
        then refreshes it every GR_REGISTER_REFRESH_HOURS."""
        return reg.configure_feed(op, kind, body.url, body.format, body.ref_field, body.name_field,
                                  body.public_key, body.max_drop_pct, body.auto_suspend, body.sheet)

    @app.post("/v1/admin/register-feeds/{kind}/approve", tags=["ops"])
    def approve_feed(kind: str, op: Operator):
        return reg.approve_feed(op, kind, allow_self=single_operator)

    @app.post("/v1/admin/register-feeds/{kind}/refresh", tags=["ops"])
    def refresh_feed(kind: str, _: Operator):
        """Check this feed now instead of waiting for the next scheduled refresh."""
        reg._feed_row(kind)
        with reg.db.tx(shared=True) as c:
            c.execute("UPDATE register_feeds SET last_checked_at=NULL WHERE kind=?", (kind,))
        reg.refresh_registers()
        return reg.feed_view(kind)

    @app.post("/v1/admin/register-feeds/{kind}/held/apply", tags=["ops"])
    def apply_held(kind: str, op: Operator):
        """Apply a refresh that was held because it removed too many entities."""
        return reg.apply_held_feed(op, kind)

    @app.delete("/v1/admin/register-feeds/{kind}/held", tags=["ops"])
    def discard_held(kind: str, op: Operator):
        return reg.discard_held_feed(op, kind)

    @app.delete("/v1/admin/register-feeds/{kind}", tags=["ops"])
    def remove_feed(kind: str, op: Operator):
        return reg.remove_feed(op, kind)

    @app.get("/v1/admin/participants", tags=["ops"])
    def all_participants(_: Operator, status: str | None = None):
        return reg.list_participants(status)

    @app.get("/v1/admin/participants/{participant_id}", tags=["ops"])
    def one_participant(participant_id: str, _: Operator):
        return reg.participant_view(participant_id)

    @app.post("/v1/admin/participants/{participant_id}/approve", tags=["ops"])
    def approve_participant(participant_id: str, op: Operator):
        """Approve the pending activation, reinstatement or capability grant (four-eyes)."""
        return reg.approve_participant_request(op, participant_id, allow_self=single_operator)

    @app.post("/v1/admin/participants/{participant_id}/reject", tags=["ops"])
    def reject_participant(participant_id: str, op: Operator):
        return reg.reject_participant_request(op, participant_id)

    @app.post("/v1/admin/participants/{participant_id}/suspend", tags=["ops"])
    def suspend_participant(participant_id: str, body: ReasonIn, op: Operator):
        return reg.suspend_participant(op, participant_id, body.reason)

    @app.post("/v1/admin/participants/{participant_id}/reinstate", tags=["ops"])
    def reinstate_participant(participant_id: str, op: Operator):
        """Request reinstatement; another operator approves it."""
        return reg.request_reinstatement(op, participant_id)

    @app.put("/v1/admin/participants/{participant_id}/capabilities", tags=["ops"])
    def participant_capabilities(participant_id: str, body: CapabilitiesIn, op: Operator):
        """Removals apply at once; additions wait for another operator's approval."""
        return reg.set_participant_capabilities(op, participant_id, body.capabilities)

    @app.post("/v1/admin/participants/{participant_id}/offboard", tags=["ops"])
    def offboard_participant(participant_id: str, body: ReasonIn, op: Operator):
        return reg.offboard_participant(op, participant_id, body.reason)

    @app.get("/v1/admin/audit/verify", tags=["ops"])
    def verify_audit(_: Operator):
        v = reg.verify_audit()
        return {"ok": v.ok, "entries": v.entries, "first_bad_seq": v.first_bad_seq, "head": v.head}

    @app.post("/v1/admin/sweep", tags=["ops"])
    def run_sweep(_: Operator):
        """Run one worker iteration now (the background worker does this every few seconds)."""
        swept = reg.sweep()
        d = dispatcher.run_once()
        return {**swept, "delivered": d.sent, "retried": d.retried, "failed": d.failed, "skipped": d.skipped}

    # ------------------------------------------------------------- sign-in
    @app.post("/v1/auth/otp", status_code=202, tags=["sign-in"])
    def request_otp(body: OtpIn, request: Request):
        limited(otp_limiter, client_ip(request))
        code = reg.request_otp(body.mobile, sms, body.language)
        out = {"sent": True, "expires_in_seconds": OTP_TTL_MINUTES * 60}
        if dev_echo and code:
            out["dev_code"] = code  # development only; refused in production
        return out

    @app.post("/v1/auth/challenge", tags=["sign-in"])
    def auth_challenge(request: Request):
        """One-time challenge for the app's device key to sign at sign-in (valid 5 minutes)."""
        limited(otp_limiter, "challenge:" + client_ip(request))
        return reg.new_challenge()

    @app.post("/v1/auth/verify", tags=["sign-in"])
    def verify_otp(body: VerifyIn, request: Request):
        limited(otp_limiter, "verify:" + client_ip(request))
        out = reg.verify_otp(body.mobile, body.code, body.display_name, body.device_id, body.device_key,
                             body.device_proof, body.challenge, body.key_attestation, body.platform,
                             adult=body.adult)
        lang = messages.normalise(body.language)
        if lang:  # an app in a language we don't have (yet) keeps English rather than failing sign-in
            reg.set_language(out["user_id"], lang)
        return out

    @app.post("/v1/recovery/start", status_code=202, tags=["sign-in"])
    def recovery_start(body: RecoveryStartIn, request: Request):
        """Lost your number and have no phone signed in? Prove the new number (get a code with
        /v1/auth/otp first) and name the old one. Same answer whether or not an account matches."""
        limited(otp_limiter, "recover:" + client_ip(request))
        return reg.start_recovery(body.old_mobile, body.new_mobile, body.code)

    @app.post("/v1/recovery/status", tags=["sign-in"])
    def recovery_status(body: RecoveryTokenIn):
        return reg.recovery_status(body.recovery_token)

    @app.post("/v1/auth/logout", status_code=204, tags=["sign-in"])
    def logout(body: LogoutIn, _: User, token: Annotated[str | None, Depends(bearer_token)]):
        reg.logout(token, everywhere=body.everywhere)

    # --------------------------------------------------------- participants
    @app.post("/v1/checks/{check_id}/fraud-label", tags=["banks"])
    def label_check(check_id: str, body: FraudLabelIn, pid: Participant):
        """Once you know: was this payment fraud (the customer reported it and you confirmed) or
        genuine? Labels tune the scam signals for everyone; they never change the check."""
        return reg.label_check(pid, check_id, body.fraud, body.note, participant_id=pid)

    @app.post("/v1/signals/fraud-payees", status_code=201, tags=["banks"])
    def report_fraud_payee(body: FraudPayeeIn, pid: Participant):
        """Report a payee after you confirmed a fraud. Every bank's protected customers are then
        held (one bank) or blocked (two banks, or an operator's confirmation) when paying it."""
        return reg.report_fraud_payee(pid, body.payee, body.reason, body.evidence_ref)

    @app.get("/v1/signals/fraud-payees/{payee}", tags=["banks"])
    def fraud_payee_status(payee: str, pid: Participant):
        """Status only: none, reported or confirmed, and how many banks (never which)."""
        reg._require_participant(pid, "checks")
        return reg.payee_status(payee)

    @app.delete("/v1/signals/fraud-payees/{payee}", tags=["banks"])
    def withdraw_fraud_payee(payee: str, pid: Participant):
        return reg.withdraw_fraud_report(pid, payee)

    @app.post("/v1/checks", tags=["banks"])
    def create_check(body: CheckIn, pid: Participant):
        limited(check_limiter, pid)
        out = reg.check(pid, body.mobile, body.participant_txn_id, body.amount, body.payee, body.channel, body.kind,
                        body.narration)
        metrics.inc("gr_checks_total", {"status": str(out.get("status"))})
        return out

    @app.get("/v1/checks/{check_id}", tags=["banks"])
    def read_check(check_id: str, pid: Participant):
        limited(check_limiter, pid)
        return reg.get_check(pid, check_id)

    @app.post("/v1/checks/{check_id}/outcome", tags=["banks"])
    def check_outcome(check_id: str, body: OutcomeIn, pid: Participant):
        return reg.report_outcome(pid, check_id, body.completed)

    @app.post("/v1/kyc/attestations", status_code=201, tags=["banks"])
    def attest(body: AttestIn, pid: Participant):
        return reg.attest(pid, body.mobile, body.kyc_level, body.customer_ref, body.verified_on, body.date_of_birth)

    @app.get("/v1/kyc/attestations/{attestation_id}", tags=["banks"])
    def read_attestation(attestation_id: str, pid: Participant):
        return reg.bank_attestation(pid, attestation_id)

    @app.delete("/v1/kyc/attestations/{attestation_id}", tags=["banks"])
    def revoke_attestation(attestation_id: str, pid: Participant):
        return reg.revoke_attestation(pid, attestation_id)

    @app.post("/v1/signals/sim-change", tags=["banks"])
    def sim_change(body: SimChangeIn, pid: Participant):
        """Report that a customer's SIM changed (from your mobile-operator data)."""
        return reg.report_sim_change(pid, body.mobile, body.changed_at)

    @app.post("/v1/signals/operator-events", tags=["banks"])
    def operator_events(body: OperatorEventsIn, pid: Participant):
        """Mobile operators: push SIM swaps, port-outs and disconnections (up to 500 per call).
        Each event gets its own result; resending an event_id is a no-op."""
        limited(check_limiter, pid)
        return reg.ingest_operator_events(pid, [e.model_dump() for e in body.events])

    @app.post("/v1/kyc/recovery-vouch", tags=["banks"])
    def bank_recovery_vouch(body: BankRecoveryIn, pid: Participant):
        """You have seen this customer (branch or video KYC) and they are recovering their
        account to new_mobile. customer_ref must match the id you attested with before."""
        return reg.bank_vouch_recovery(pid, body.new_mobile, body.customer_ref, assisted=body.assisted,
                                       verified_on=body.verified_on, date_of_birth=body.date_of_birth)

    @app.get("/v1/participant/certificates", tags=["banks"])
    def my_certs(pid: Participant):
        return reg.participant_certs(pid)

    @app.post("/v1/participant/certificates", status_code=201, tags=["banks"])
    def rotate_cert(body: CertIn, pid: Participant, request: Request):
        """Add your next certificate. Must be called over mutual TLS with a pinned one."""
        return reg.rotate_cert(pid, request.state.client_cert, body.certificate)

    @app.delete("/v1/participant/certificates/{fingerprint}", tags=["banks"])
    def remove_my_cert(fingerprint: str, pid: Participant, request: Request):
        return reg.remove_cert_pin(pid, pid, fingerprint, presented=request.state.client_cert)

    @app.get("/v1/participant/me", tags=["banks"])
    def participant_me(pid: Participant):
        """Your status and capabilities. Works while pending, so you can check onboarding."""
        return reg.participant_view(pid)

    @app.put("/v1/participant/webhook", tags=["banks"])
    def set_webhook(body: WebhookIn, pid: Participant):
        """Receive signed `check.updated` events instead of polling. Verify X-GR-Signature as
        'sha256=' + HMAC-SHA256(webhook_secret, raw body)."""
        return reg.set_webhook(pid, body.url)

    @app.post("/v1/participant/rotate-key", tags=["banks"])
    def rotate_key(pid: Participant):
        return reg.rotate_participant_key(pid)

    # ------------------------------------------------------------ principal
    @app.get("/v1/me", tags=["people"])
    def me(uid: User):
        return reg.profile(uid)

    @app.put("/v1/me/language", tags=["people"])
    def set_language(body: LanguageIn, uid: User):
        """Language for your alerts, SMS and messages (English or Hindi)."""
        return reg.set_language(uid, messages.normalise(body.language) or body.language)

    # ------------------------------------------------------- SIM-swap safety
    def screen_lang(request: Request) -> str:
        return messages.language_from_header(request.headers.get("accept-language"))

    def with_reasons_in(lang: str, payments: list[dict]) -> list[dict]:
        """Payment reasons are stored in English; people read them in their language."""
        if lang == "en":
            return payments
        return [{**p, "reasons": [messages.phrase(r, lang) for r in p.get("reasons") or []]} for p in payments]

    @app.get("/v1/me/security", tags=["people"])
    def my_security(info: Session, request: Request):
        lang = screen_lang(request)
        return {**reg.security_status(info["user_id"], info["user_id"]),
                "this_session": {"restricted": info["restricted"],
                                 "reasons": [messages.restriction(r, lang) for r in info["reasons"]]}}

    @app.post("/v1/me/security/lost-phone", tags=["people"])
    def my_lost_phone(uid: User):
        """Signs you out everywhere (this session too) and opens the SIM-swap window."""
        return reg.report_lost_phone(uid, uid)

    @app.post("/v1/me/security/confirm-sim-change", tags=["people"])
    def my_confirm_sim(uid: TrustedUser):
        return reg.confirm_sim_change(uid, uid)

    @app.post("/v1/me/mobile/change", status_code=202, tags=["people"])
    def change_mobile(body: NewMobileIn, uid: TrustedUser, request: Request):
        limited(otp_limiter, client_ip(request))
        code = reg.request_mobile_change(uid, body.new_mobile, sms)
        out = {"sent": True, "expires_in_seconds": OTP_TTL_MINUTES * 60}
        if dev_echo and code:
            out["dev_code"] = code
        return out

    @app.post("/v1/me/mobile/verify", tags=["people"])
    def verify_mobile(body: NewMobileVerifyIn, uid: TrustedUser):
        return reg.confirm_mobile_change(uid, body.new_mobile, body.code)

    @app.get("/v1/me/recoveries", tags=["people"])
    def my_recoveries(uid: User):
        return reg.my_recoveries(uid)

    @app.post("/v1/me/recoveries/{recovery_id}/cancel", tags=["people"])
    def cancel_recovery(recovery_id: str, uid: User):
        """'That isn't me.' Works from any session, even a restricted one: stopping is protective."""
        return reg.cancel_recovery(uid, recovery_id)

    @app.get("/v1/me/identity", tags=["people"])
    def my_identity(uid: User):
        return reg.identity(uid)

    @app.post("/v1/me/identity/attestations/{attestation_id}/approve", tags=["people"])
    def approve_attestation(attestation_id: str, uid: TrustedUser):
        return reg.respond_to_attestation(uid, attestation_id, True)

    @app.post("/v1/me/identity/attestations/{attestation_id}/reject", tags=["people"])
    def reject_attestation(attestation_id: str, uid: User):
        return reg.respond_to_attestation(uid, attestation_id, False)

    @app.delete("/v1/me/identity/attestations/{attestation_id}", tags=["people"])
    def withdraw_attestation(attestation_id: str, uid: User):
        return reg.withdraw_attestation(uid, attestation_id)

    @app.get("/v1/me/devices", tags=["people"])
    def my_devices(uid: User):
        return reg.device_keys(uid)

    @app.delete("/v1/me/devices/{key_id}", tags=["people"])
    def remove_device(key_id: str, uid: TrustedUser):
        """Revoke one device key and sign that device out. Needs a trusted session, so a thief
        can't remove the owner's phone."""
        return reg.revoke_device_key(uid, key_id)

    @app.get("/v1/me/alerts", tags=["people"])
    def my_alerts(uid: User):
        return reg.alert_settings(uid)

    @app.put("/v1/me/alerts", tags=["people"])
    def set_alerts(body: AlertChannelIn, uid: User):
        """Urgent alerts by SMS (default) or WhatsApp."""
        return reg.set_urgent_channel(uid, body.urgent_channel)

    @app.post("/v1/me/alerts/push", status_code=201, tags=["people"])
    def add_push(body: PushTokenIn, uid: User):
        """Register this app install for push alerts. Push keeps working during a SIM swap."""
        return reg.add_push_token(uid, body.token, body.platform)

    @app.delete("/v1/me/alerts/push/{token_id}", tags=["people"])
    def remove_push(token_id: str, uid: User):
        return reg.remove_push_token(uid, token_id)

    @app.get("/v1/me/notifications", tags=["people"])
    def my_notifications(uid: User, unread_only: bool = False, limit: int = 50):
        return reg.notifications(uid, unread_only, min(max(limit, 1), 200))

    @app.post("/v1/me/notifications/read", tags=["people"])
    def read_notifications(body: ReadIn, uid: User):
        return {"marked": reg.mark_read(uid, body.ids)}

    @app.get("/v1/presets", tags=["people"])
    def presets(request: Request):
        return messages.preset_labels(PRESETS, screen_lang(request))

    # --------------------------------------------------------- privacy (DPDP Act)
    @app.get("/v1/languages", tags=["people"])
    def languages():
        """Languages for alerts, SMS and messages. Drafts appear only once reviewed and enabled."""
        meta = messages.language_meta()
        return [{"code": c, "name": meta[c]["name"]} for c in messages.enabled_languages()]

    @app.put("/v1/me/name", tags=["people"])
    def correct_name(body: NameIn, uid: User):
        """Correct the name you're shown by (DPDP Act s.12)."""
        return reg.set_display_name(uid, body.display_name)

    @app.get("/v1/me/nominee", tags=["people"])
    def get_nominee(uid: User):
        return {"nominee": reg.nominee(uid)}

    @app.put("/v1/me/nominee", tags=["people"])
    def put_nominee(body: NomineeIn, uid: TrustedUser):
        """Nominate someone to exercise your data rights if you die or can't act (DPDP Act s.14). It gives
        them no access to your account and no say over payments."""
        return {"nominee": reg.set_nominee(uid, body.name, body.relation, body.mobile)}

    @app.delete("/v1/me/nominee", tags=["people"])
    def delete_nominee(uid: TrustedUser):
        reg.remove_nominee(uid)
        return {"nominee": None}

    @app.get("/v1/privacy/notice", tags=["people"])
    def privacy_notice(request: Request):
        """What we collect, why, for how long, your rights and the grievance officer. In Hindi when
        Accept-Language asks for it (same version)."""
        return reg.privacy_notice(screen_lang(request))

    @app.get("/v1/me/consents", tags=["people"])
    def my_consents(uid: User):
        return reg.consents(uid)

    @app.post("/v1/me/consents", tags=["people"])
    def accept_notice(body: ConsentIn, uid: User):
        return reg.record_consent(uid, body.notice_version)

    @app.get("/v1/me/data-export", tags=["people"])
    def data_export(uid: TrustedUser):
        """Everything held about you, as JSON. Needs a session that isn't restricted by a SIM
        change, since it includes your number and date of birth."""
        return JSONResponse(reg.data_export(uid), headers={
            "Content-Disposition": 'attachment; filename="guardian-registry-my-data.json"'})

    @app.post("/v1/me/erasure", status_code=202, tags=["people"])
    def request_erasure(uid: TrustedUser):
        """Delete my account. Held for 7 days (your guardians are told; you can cancel)."""
        return reg.request_erasure(uid)

    @app.get("/v1/me/erasure", tags=["people"])
    def erasure_status(uid: User):
        """The waiting deletion, if any: {"erasure": {"status": "pending", "erase_at": ...}} or {"erasure": null}."""
        e = reg.erasure_request(uid)
        return {"erasure": e if e and e["status"] == "pending" else None}

    @app.delete("/v1/me/erasure", tags=["people"])
    def cancel_erasure(uid: User):
        return reg.cancel_erasure(uid)

    @app.get("/v1/me/rules", tags=["people"])
    def my_rules(uid: User):
        return reg.get_rules(uid).to_dict()

    @app.patch("/v1/me/rules", tags=["people"])
    @app.put("/v1/me/rules", tags=["people"], summary="Patch Rules (for clients that can't send PATCH)")
    def patch_rules(body: RulesPatch, info: Session):
        changes = body.model_dump(exclude_unset=True)
        if info["restricted"] and reg.would_loosen(info["user_id"], changes):
            raise restricted_error(info)
        return reg.update_rules(info["user_id"], changes)

    @app.post("/v1/me/rules/preset/{name}", tags=["people"])
    def apply_preset(name: str, info: Session):
        if info["restricted"] and name in PRESETS and reg.would_loosen(info["user_id"], PRESETS[name]["rules"]):
            raise restricted_error(info)
        return reg.apply_preset(info["user_id"], name)

    @app.post("/v1/me/kill-switch/on", tags=["people"])
    def my_kill_on(uid: User):
        return reg.engage_kill_switch(uid, uid).to_dict()

    @app.post("/v1/me/kill-switch/off", tags=["people"])
    def my_kill_off(uid: TrustedUser):
        return reg.release_kill_switch(uid, uid)

    @app.get("/v1/me/guardians", tags=["people"])
    def my_guardians(uid: User):
        return reg.guardians_of(uid)

    @app.post("/v1/me/guardians", status_code=201, tags=["people"])
    def invite(body: InviteIn, uid: TrustedUser):
        return reg.invite_guardian(uid, body.mobile)

    @app.delete("/v1/me/guardians/{guardianship_id}", tags=["people"])
    def remove(guardianship_id: str, uid: TrustedUser):
        return reg.remove_guardian(uid, guardianship_id)

    @app.get("/v1/me/changes", tags=["people"])
    def my_changes(uid: User):
        return reg.changes_for(uid)

    @app.get("/v1/me/payments", tags=["people"])
    def my_payments(uid: User, request: Request, limit: int = 50):
        return with_reasons_in(screen_lang(request), reg.history(uid, uid, min(max(limit, 1), 200)))

    @app.post("/v1/me/payments/{check_id}/cancel", tags=["people"])
    def my_cancel(check_id: str, uid: User):
        return reg.cancel_check(uid, check_id)

    @app.get("/v1/me/audit", tags=["people"])
    def my_audit(uid: User):
        return reg.audit_trail(uid, uid)

    # -------------------------------------------------------------- guardian
    @app.get("/v1/guardian/inbox", tags=["guardians"])
    def inbox(uid: User, request: Request):
        out = reg.inbox(uid)
        return {**out, "held_payments": with_reasons_in(screen_lang(request), out.get("held_payments") or [])}

    @app.get("/v1/guardian/recoveries", tags=["guardians"])
    def recoveries(uid: User):
        """Recoveries you are asked to vouch for (you guard them, or they guard you)."""
        return reg.recoveries_to_vouch(uid)

    @app.post("/v1/guardian/recoveries/{recovery_id}/approve", tags=["guardians"])
    def approve_recovery(recovery_id: str, uid: TrustedUser):
        return reg.vouch_recovery(uid, recovery_id, True)

    @app.post("/v1/guardian/recoveries/{recovery_id}/deny", tags=["guardians"])
    def deny_recovery(recovery_id: str, uid: User):
        return reg.vouch_recovery(uid, recovery_id, False)

    @app.get("/v1/guardian/wards", tags=["guardians"])
    def wards(uid: User):
        return reg.wards_of(uid)

    @app.post("/v1/guardian/invitations/{guardianship_id}/accept", tags=["guardians"])
    def accept(guardianship_id: str, uid: TrustedUser):
        return reg.respond_to_invite(uid, guardianship_id, True)

    @app.post("/v1/guardian/invitations/{guardianship_id}/decline", tags=["guardians"])
    def decline(guardianship_id: str, uid: User):
        return reg.respond_to_invite(uid, guardianship_id, False)

    @app.post("/v1/guardian/guardianships/{guardianship_id}/resign", tags=["guardians"])
    def resign(guardianship_id: str, uid: User):
        return reg.resign(uid, guardianship_id)

    @app.post("/v1/guardian/payments/{check_id}/approve", tags=["guardians"])
    def approve(check_id: str, uid: TrustedUser):
        return reg.approve_check(uid, check_id)

    @app.post("/v1/guardian/payments/{check_id}/deny", tags=["guardians"])
    def deny(check_id: str, uid: User):
        return reg.deny_check(uid, check_id)

    @app.post("/v1/guardian/payments/{check_id}/cancel", tags=["guardians"])
    def g_cancel(check_id: str, uid: User):
        return reg.cancel_check(uid, check_id)

    @app.post("/v1/guardian/changes/{change_id}/approve", tags=["guardians"])
    def approve_change(change_id: str, uid: TrustedUser):
        return reg.approve_change(uid, change_id)

    @app.post("/v1/guardian/changes/{change_id}/veto", tags=["guardians"])
    def veto_change(change_id: str, uid: User):
        return reg.veto_change(uid, change_id)

    @app.get("/v1/guardian/wards/{principal_id}/rules", tags=["guardians"])
    def ward_rules(principal_id: str, uid: User):
        reg._require_guardian(principal_id, uid)
        return reg.get_rules(principal_id).to_dict()

    @app.get("/v1/guardian/wards/{principal_id}/payments", tags=["guardians"])
    def ward_payments(principal_id: str, uid: User, limit: int = 50):
        return reg.history(uid, principal_id, min(max(limit, 1), 200))

    @app.get("/v1/guardian/wards/{principal_id}/audit", tags=["guardians"])
    def ward_audit(principal_id: str, uid: User):
        return reg.audit_trail(uid, principal_id)

    @app.post("/v1/guardian/wards/{principal_id}/kill-switch/on", tags=["guardians"])
    def ward_kill_on(principal_id: str, uid: User):
        return reg.engage_kill_switch(principal_id, uid).to_dict()

    @app.post("/v1/guardian/wards/{principal_id}/kill-switch/off", tags=["guardians"])
    def ward_kill_off(principal_id: str, uid: TrustedUser):
        return reg.release_kill_switch(principal_id, uid)

    @app.get("/v1/guardian/wards/{principal_id}/security", tags=["guardians"])
    def ward_security(principal_id: str, uid: User):
        return reg.security_status(uid, principal_id)

    @app.post("/v1/guardian/wards/{principal_id}/lost-phone", tags=["guardians"])
    def ward_lost_phone(principal_id: str, uid: User):
        return reg.report_lost_phone(uid, principal_id)

    @app.post("/v1/guardian/wards/{principal_id}/confirm-sim-change", tags=["guardians"])
    def ward_confirm_sim(principal_id: str, uid: TrustedUser):
        return reg.confirm_sim_change(uid, principal_id)

    @app.post("/v1/guardian/wards/{principal_id}/trusted-payees", status_code=201, tags=["guardians"])
    def vouch(principal_id: str, body: PayeeIn, uid: TrustedUser):
        reg.vouch_payee(uid, principal_id, body.payee)
        return {"trusted_payees": reg.trusted_payees(principal_id)}

    return app
