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

import logging
import math
import os
import secrets
import threading
from contextlib import asynccontextmanager
from typing import Annotated, Literal

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .db import Database
from .errors import RegistryError
from .models import CHANNELS
from .notify import Dispatcher, SmsSender, sms_sender_from_env
from .participants import CAPABILITIES, PARTICIPANT_KINDS
from .presets import PRESETS
from .ratelimit import RateLimiter
from .security import check_production_config, is_production
from .service import OTP_TTL_MINUTES, Registry

log = logging.getLogger("guardian_registry.api")


# ----------------------------------------------------------------- schemas
class OtpIn(BaseModel):
    mobile: str


class VerifyIn(BaseModel):
    mobile: str
    code: str = Field(min_length=4, max_length=10)
    display_name: str | None = Field(default=None, max_length=80)
    device_id: str | None = Field(default=None, max_length=200,
                                  description="stable app-install id; new devices start on probation")


class SimChangeIn(BaseModel):
    mobile: str
    changed_at: str | None = Field(default=None, description="ISO 8601 with timezone; default now")


class NewMobileIn(BaseModel):
    new_mobile: str


class NewMobileVerifyIn(BaseModel):
    new_mobile: str
    code: str = Field(min_length=4, max_length=10)


class LogoutIn(BaseModel):
    everywhere: bool = False


class ParticipantIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    kind: Literal[tuple(PARTICIPANT_KINDS)] = "bank"  # type: ignore[valid-type]
    regulator_ref: str = Field(min_length=3, max_length=60,
                               description="licence / registration number, e.g. RBI or NPCI reference")
    capabilities: list[Literal[CAPABILITIES]] | None = Field(  # type: ignore[valid-type]
        default=None, description="default: the usual set for this kind")


class ReasonIn(BaseModel):
    reason: str = Field(min_length=3, max_length=300)


class CapabilitiesIn(BaseModel):
    capabilities: list[Literal[CAPABILITIES]]  # type: ignore[valid-type]


class WebhookIn(BaseModel):
    url: str | None = Field(default=None, max_length=500)


class InviteIn(BaseModel):
    mobile: str


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


class AttestIn(BaseModel):
    """A bank vouches that it has KYC'd this registry user. The customer must approve it."""
    mobile: str
    kyc_level: Literal["full", "minimum"]
    customer_ref: str = Field(min_length=1, max_length=100, description="your own customer id; stored only hashed")
    verified_on: str = Field(description="date KYC was completed, YYYY-MM-DD")
    date_of_birth: str | None = Field(default=None, description="optional, YYYY-MM-DD; only a senior yes/no is shared")


class PayeeIn(BaseModel):
    payee: str = Field(min_length=1, max_length=200)


class ReadIn(BaseModel):
    ids: list[str] | None = None


class CheckIn(BaseModel):
    mobile: str
    participant_txn_id: str = Field(min_length=1, max_length=100)
    amount: int = Field(description="paise")
    payee: str = Field(min_length=1, max_length=200)
    channel: Literal[CHANNELS] = "upi"  # type: ignore[valid-type]


class OutcomeIn(BaseModel):
    completed: bool


# ------------------------------------------------------------------ worker
class Worker(threading.Thread):
    """Background loop: move time-based state forward, then deliver alerts and webhooks."""

    def __init__(self, registry: Registry, dispatcher: Dispatcher, interval: float):
        super().__init__(name="guardian-registry-worker", daemon=True)
        self.registry, self.dispatcher, self.interval = registry, dispatcher, interval
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                self.registry.sweep()
                self.dispatcher.run_once()
            except Exception:  # noqa: BLE001 - keep the loop alive, log and continue
                log.exception("worker iteration failed")
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
    sms: SmsSender | None = None,
    http: httpx.Client | None = None,
    run_worker: bool | None = None,
    check_rate: str | None = None,
    otp_rate: str | None = None,
) -> FastAPI:
    check_production_config()
    pkg_log = logging.getLogger("guardian_registry")
    if not pkg_log.handlers:  # make dev SMS / worker messages visible next to uvicorn's own logs
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s:     %(name)s: %(message)s"))
        pkg_log.addHandler(handler)
        pkg_log.setLevel(logging.INFO)
    reg = registry or Registry(Database(os.environ.get("GR_DB", "guardian_registry.db")))
    if operators is None:
        operators = parse_operators(os.environ.get("GR_OPERATORS"))
        admin = admin_token if admin_token is not None else os.environ.get("GR_ADMIN_TOKEN")
        if admin and not operators:
            operators = {"admin": admin}
    operators = {k: v for k, v in operators.items() if v}
    if is_production() and len(operators) == 1:
        raise RuntimeError("unsafe production config: set GR_OPERATORS with at least two operators "
                           "(participant onboarding needs a second approver)")
    single_operator = len(operators) == 1  # dev convenience: approves its own requests
    sms = sms or sms_sender_from_env()
    dispatcher = Dispatcher(reg.db, reg.clock, sms=sms, http=http)
    if run_worker is None:
        run_worker = os.environ.get("GR_WORKER", "1") == "1"
    worker_interval = float(os.environ.get("GR_WORKER_INTERVAL", "5"))
    check_limiter = RateLimiter.parse(check_rate or os.environ.get("GR_RATE_CHECKS", "600/60"))
    otp_limiter = RateLimiter.parse(otp_rate or os.environ.get("GR_RATE_OTP", "10/60"))
    dev_echo = os.environ.get("GR_OTP_DEV_ECHO") == "1" and not is_production()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        worker = Worker(reg, dispatcher, worker_interval) if run_worker else None
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

    @app.exception_handler(RegistryError)
    async def _registry_error(_: Request, exc: RegistryError):
        return JSONResponse(status_code=exc.status, content={"error": type(exc).__name__, "detail": str(exc)})

    @app.exception_handler(HTTPException)
    async def _http_error(_: Request, exc: HTTPException):
        body = exc.detail if isinstance(exc.detail, dict) else {"detail": exc.detail}
        return JSONResponse(status_code=exc.status_code, content=body, headers=getattr(exc, "headers", None))

    def limited(limiter: RateLimiter, key: str) -> None:
        ok, retry = limiter.hit(key)
        if not ok:
            raise HTTPException(429, "rate limit exceeded", headers={"Retry-After": str(math.ceil(retry) or 1)})

    # ------------------------------------------------------------- auth deps
    def participant(x_api_key: Annotated[str | None, Header()] = None) -> str:
        pid = reg.participant_by_key(x_api_key) if x_api_key else None
        if not pid:
            raise HTTPException(401, "missing or invalid X-Api-Key")
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

    def trusted_user(info: Annotated[dict, Depends(session)]) -> str:
        """For actions a phone-number thief must not be able to take (see simswap.py)."""
        if info["restricted"]:
            raise restricted_error(info)
        return info["user_id"]

    def operator(x_admin_token: Annotated[str | None, Header()] = None) -> str:
        if not operators:
            raise HTTPException(503, "admin API disabled: set GR_OPERATORS (or GR_ADMIN_TOKEN in development)")
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

    # ------------------------------------------------------------------ ops
    @app.get("/healthz", tags=["ops"])
    def healthz():
        return {"ok": True, "version": __version__}

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
        limited(otp_limiter, request.client.host if request.client else "unknown")
        code = reg.request_otp(body.mobile, sms)
        out = {"sent": True, "expires_in_seconds": OTP_TTL_MINUTES * 60}
        if dev_echo:
            out["dev_code"] = code  # development only; refused in production
        return out

    @app.post("/v1/auth/verify", tags=["sign-in"])
    def verify_otp(body: VerifyIn, request: Request):
        limited(otp_limiter, "verify:" + (request.client.host if request.client else "unknown"))
        return reg.verify_otp(body.mobile, body.code, body.display_name, body.device_id)

    @app.post("/v1/auth/logout", status_code=204, tags=["sign-in"])
    def logout(body: LogoutIn, _: User, token: Annotated[str | None, Depends(bearer_token)]):
        reg.logout(token, everywhere=body.everywhere)

    # --------------------------------------------------------- participants
    @app.post("/v1/checks", tags=["banks"])
    def create_check(body: CheckIn, pid: Participant):
        limited(check_limiter, pid)
        return reg.check(pid, body.mobile, body.participant_txn_id, body.amount, body.payee, body.channel)

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

    # ------------------------------------------------------- SIM-swap safety
    @app.get("/v1/me/security", tags=["people"])
    def my_security(info: Session):
        return {**reg.security_status(info["user_id"], info["user_id"]),
                "this_session": {"restricted": info["restricted"], "reasons": info["reasons"]}}

    @app.post("/v1/me/security/lost-phone", tags=["people"])
    def my_lost_phone(uid: User):
        """Signs you out everywhere (this session too) and opens the SIM-swap window."""
        return reg.report_lost_phone(uid, uid)

    @app.post("/v1/me/security/confirm-sim-change", tags=["people"])
    def my_confirm_sim(uid: TrustedUser):
        return reg.confirm_sim_change(uid, uid)

    @app.post("/v1/me/mobile/change", status_code=202, tags=["people"])
    def change_mobile(body: NewMobileIn, uid: TrustedUser, request: Request):
        limited(otp_limiter, request.client.host if request.client else "unknown")
        code = reg.request_mobile_change(uid, body.new_mobile, sms)
        out = {"sent": True, "expires_in_seconds": OTP_TTL_MINUTES * 60}
        if dev_echo:
            out["dev_code"] = code
        return out

    @app.post("/v1/me/mobile/verify", tags=["people"])
    def verify_mobile(body: NewMobileVerifyIn, uid: TrustedUser):
        return reg.confirm_mobile_change(uid, body.new_mobile, body.code)

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

    @app.get("/v1/me/notifications", tags=["people"])
    def my_notifications(uid: User, unread_only: bool = False, limit: int = 50):
        return reg.notifications(uid, unread_only, min(max(limit, 1), 200))

    @app.post("/v1/me/notifications/read", tags=["people"])
    def read_notifications(body: ReadIn, uid: User):
        return {"marked": reg.mark_read(uid, body.ids)}

    @app.get("/v1/presets", tags=["people"])
    def presets():
        return PRESETS

    @app.get("/v1/me/rules", tags=["people"])
    def my_rules(uid: User):
        return reg.get_rules(uid).to_dict()

    @app.patch("/v1/me/rules", tags=["people"])
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
    def my_payments(uid: User, limit: int = 50):
        return reg.history(uid, uid, min(max(limit, 1), 200))

    @app.post("/v1/me/payments/{check_id}/cancel", tags=["people"])
    def my_cancel(check_id: str, uid: User):
        return reg.cancel_check(uid, check_id)

    @app.get("/v1/me/audit", tags=["people"])
    def my_audit(uid: User):
        return reg.audit_trail(uid, uid)

    # -------------------------------------------------------------- guardian
    @app.get("/v1/guardian/inbox", tags=["guardians"])
    def inbox(uid: User):
        return reg.inbox(uid)

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
