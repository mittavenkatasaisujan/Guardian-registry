"""HTTP API.

Three kinds of caller:
  * Banks / payment apps ("participants") send `X-Api-Key` and call /v1/checks.
  * People (principals and guardians) send `Authorization: Bearer <token>`.
  * Operators send `X-Admin-Token` (set GR_ADMIN_TOKEN) to onboard participants.

Run:  uvicorn guardian_registry.api:create_app --factory --port 8000
"""


import os
import secrets
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import __version__
from .db import Database
from .errors import RegistryError
from .models import CHANNELS
from .service import Registry


# ----------------------------------------------------------------- schemas
class EnrolIn(BaseModel):
    mobile: str
    display_name: str = Field(min_length=1, max_length=80)


class ParticipantIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)


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


class PayeeIn(BaseModel):
    payee: str = Field(min_length=1, max_length=200)


class CheckIn(BaseModel):
    mobile: str
    participant_txn_id: str = Field(min_length=1, max_length=100)
    amount: int = Field(description="paise")
    payee: str = Field(min_length=1, max_length=200)
    channel: Literal[CHANNELS] = "upi"  # type: ignore[valid-type]


class OutcomeIn(BaseModel):
    completed: bool


def create_app(registry: Registry | None = None, admin_token: str | None = None) -> FastAPI:
    reg = registry or Registry(Database(os.environ.get("GR_DB", "guardian_registry.db")))
    admin = admin_token if admin_token is not None else os.environ.get("GR_ADMIN_TOKEN")

    app = FastAPI(title="Guardian Registry", version=__version__,
                  description="Cross-bank trusted-person and payment-protection registry.")
    app.state.registry = reg

    @app.exception_handler(RegistryError)
    async def _registry_error(_: Request, exc: RegistryError):
        return JSONResponse(status_code=exc.status, content={"error": type(exc).__name__, "detail": str(exc)})

    # ------------------------------------------------------------- auth deps
    def participant(x_api_key: Annotated[str | None, Header()] = None) -> str:
        pid = reg.participant_by_key(x_api_key) if x_api_key else None
        if not pid:
            raise HTTPException(401, "missing or invalid X-Api-Key")
        return pid

    def user(authorization: Annotated[str | None, Header()] = None) -> str:
        token = authorization[7:] if authorization and authorization.lower().startswith("bearer ") else None
        uid = reg.user_by_token(token) if token else None
        if not uid:
            raise HTTPException(401, "missing or invalid bearer token")
        return uid

    def operator(x_admin_token: Annotated[str | None, Header()] = None) -> None:
        if not admin:
            raise HTTPException(503, "admin API disabled: set GR_ADMIN_TOKEN")
        if not x_admin_token or not secrets.compare_digest(x_admin_token, admin):
            raise HTTPException(401, "invalid X-Admin-Token")

    Participant = Annotated[str, Depends(participant)]
    User = Annotated[str, Depends(user)]
    Operator = Annotated[None, Depends(operator)]

    # ------------------------------------------------------------------ ops
    @app.get("/healthz", tags=["ops"])
    def healthz():
        return {"ok": True, "version": __version__}

    @app.post("/v1/admin/participants", status_code=201, tags=["ops"])
    def add_participant(body: ParticipantIn, _: Operator):
        pid, key = reg.register_participant(body.name)
        return {"participant_id": pid, "api_key": key, "note": "store the key now; it is not shown again"}

    @app.get("/v1/admin/audit/verify", tags=["ops"])
    def verify_audit(_: Operator):
        v = reg.verify_audit()
        return {"ok": v.ok, "entries": v.entries, "first_bad_seq": v.first_bad_seq, "head": v.head}

    # --------------------------------------------------------- participants
    @app.post("/v1/checks", tags=["banks"])
    def create_check(body: CheckIn, pid: Participant):
        return reg.check(pid, body.mobile, body.participant_txn_id, body.amount, body.payee, body.channel)

    @app.get("/v1/checks/{check_id}", tags=["banks"])
    def read_check(check_id: str, pid: Participant):
        return reg.get_check(pid, check_id)

    @app.post("/v1/checks/{check_id}/outcome", tags=["banks"])
    def check_outcome(check_id: str, body: OutcomeIn, pid: Participant):
        return reg.report_outcome(pid, check_id, body.completed)

    # ------------------------------------------------------------ principal
    @app.post("/v1/users", status_code=201, tags=["people"])
    def enrol(body: EnrolIn):
        uid, token = reg.register_user(body.mobile, body.display_name)
        return {"user_id": uid, "token": token}

    @app.get("/v1/me", tags=["people"])
    def me(uid: User):
        return reg.profile(uid)

    @app.get("/v1/me/rules", tags=["people"])
    def my_rules(uid: User):
        return reg.get_rules(uid).to_dict()

    @app.patch("/v1/me/rules", tags=["people"])
    def patch_rules(body: RulesPatch, uid: User):
        return reg.update_rules(uid, body.model_dump(exclude_unset=True))

    @app.post("/v1/me/kill-switch/on", tags=["people"])
    def my_kill_on(uid: User):
        return reg.engage_kill_switch(uid, uid).to_dict()

    @app.post("/v1/me/kill-switch/off", tags=["people"])
    def my_kill_off(uid: User):
        return reg.release_kill_switch(uid, uid)

    @app.get("/v1/me/guardians", tags=["people"])
    def my_guardians(uid: User):
        return reg.guardians_of(uid)

    @app.post("/v1/me/guardians", status_code=201, tags=["people"])
    def invite(body: InviteIn, uid: User):
        return reg.invite_guardian(uid, body.mobile)

    @app.delete("/v1/me/guardians/{guardianship_id}", tags=["people"])
    def remove(guardianship_id: str, uid: User):
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
    def accept(guardianship_id: str, uid: User):
        return reg.respond_to_invite(uid, guardianship_id, True)

    @app.post("/v1/guardian/invitations/{guardianship_id}/decline", tags=["guardians"])
    def decline(guardianship_id: str, uid: User):
        return reg.respond_to_invite(uid, guardianship_id, False)

    @app.post("/v1/guardian/guardianships/{guardianship_id}/resign", tags=["guardians"])
    def resign(guardianship_id: str, uid: User):
        return reg.resign(uid, guardianship_id)

    @app.post("/v1/guardian/payments/{check_id}/approve", tags=["guardians"])
    def approve(check_id: str, uid: User):
        return reg.approve_check(uid, check_id)

    @app.post("/v1/guardian/payments/{check_id}/deny", tags=["guardians"])
    def deny(check_id: str, uid: User):
        return reg.deny_check(uid, check_id)

    @app.post("/v1/guardian/payments/{check_id}/cancel", tags=["guardians"])
    def g_cancel(check_id: str, uid: User):
        return reg.cancel_check(uid, check_id)

    @app.post("/v1/guardian/changes/{change_id}/approve", tags=["guardians"])
    def approve_change(change_id: str, uid: User):
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
    def ward_kill_off(principal_id: str, uid: User):
        return reg.release_kill_switch(principal_id, uid)

    @app.post("/v1/guardian/wards/{principal_id}/trusted-payees", status_code=201, tags=["guardians"])
    def vouch(principal_id: str, body: PayeeIn, uid: User):
        reg.vouch_payee(uid, principal_id, body.payee)
        return {"trusted_payees": reg.trusted_payees(principal_id)}

    return app
