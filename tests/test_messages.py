"""Server-written text in the person's language (messages.py)."""

import json
import re

import httpx
import pytest
from fastapi.testclient import TestClient

from guardian_registry import messages, textscan
from guardian_registry.notify import LogSmsSender
from guardian_registry.providers import MetaWhatsApp, Msg91Sms
from guardian_registry.service import OTP_RESEND_SECONDS

from .conftest import AMMA, PRIYA, R, RAVI

PLACEHOLDER = re.compile(r"\{\d+\}")


# ------------------------------------------------------------------ coverage, from the source
def test_every_alert_in_the_code_has_hindi():
    missing = sorted({t for _, _, t in textscan.alert_templates() if t not in messages.ALERTS_HI})
    assert not missing, missing


def test_every_person_facing_error_has_hindi_or_is_marked_not_for_people():
    missing = sorted({t for _, _, t in textscan.error_templates()
                      if t not in messages.ERRORS_HI and t not in messages.NOT_FOR_PEOPLE})
    assert not missing, missing


@pytest.mark.parametrize("table", ["ALERTS_HI", "FRAGMENTS_HI", "ERRORS_HI", "ERROR_FRAGMENTS_HI"])
def test_hindi_keeps_every_placeholder(table):
    for en, hi in getattr(messages, table).items():
        assert sorted(PLACEHOLDER.findall(en)) == sorted(PLACEHOLDER.findall(hi)), en


# ------------------------------------------------------------------ the engine
def test_values_pass_through_and_phrases_are_translated():
    en = ("Ravi wants to pay ₹20,000 to known@upi. Approve or deny within 30 min. Reason held: "
          "amount ₹20,000 is at or above the approval threshold ₹10,000; first payment of ₹20,000 to a new payee.")
    hi = messages.alert(en, "hi")
    assert hi.startswith("Ravi known@upi को ₹20,000 भेजना चाहते हैं।")
    assert "राशि ₹20,000 मंज़ूरी सीमा ₹10,000 के बराबर" in hi and "नए प्राप्तकर्ता को ₹20,000 का पहला भुगतान" in hi
    assert messages.alert(en, "en") == en
    assert messages.alert("Something new the catalog doesn't know", "hi") == "Something new the catalog doesn't know"


def test_language_header():
    assert messages.language_from_header("hi-IN,hi;q=0.9,en;q=0.8") == "hi"
    assert messages.language_from_header("ta-IN,en;q=0.5") == "en"
    assert messages.language_from_header(None) == "en"


ENGLISH_RUN = re.compile(r"\b[A-Za-z]{3,}(?:\s+[A-Za-z]{2,}){2,}\b")


def _english_left(text):
    """Three or more English words in a row, ignoring the registry's own name."""
    return [m for m in ENGLISH_RUN.findall(text.replace("Guardian Registry", "")) if m]


# ------------------------------------------------------------------ alerts end to end
class TestHindiAlerts:
    def test_payment_flows_reach_a_hindi_speaker_in_hindi(self, reg, family, clock):
        reg.db.conn.execute("DELETE FROM notifications")  # the fixture's alerts went out in English
        reg.set_language(family["ravi"], "hi")
        reg.set_language(family["amma"], "hi")
        bank = family["bank"]
        c1 = reg.check(bank, AMMA, "t1", 20_000 * R, "known@upi")          # needs Ravi's approval
        reg.approve_check(family["ravi"], c1["check_id"])
        c2 = reg.check(bank, AMMA, "t2", 6_000 * R, "new@upi")             # cooling-off
        reg.cancel_check(family["amma"], c2["check_id"])
        reg.engage_kill_switch(family["amma"], family["ravi"])
        reg.check(bank, AMMA, "t3", 100 * R, "known@upi")                  # blocked while paused
        rows = reg.db.all("SELECT kind, title, body FROM notifications WHERE recipient_type='user' "
                          "AND channel='inapp'")
        assert rows
        leftovers = {r["kind"]: _english_left(r["title"] + " " + r["body"]) for r in rows}
        assert not {k: v for k, v in leftovers.items() if v}, leftovers
        assert any("मंज़ूर करें" in r["title"] for r in rows)

    def test_sim_change_and_guardian_events(self, reg, family):
        reg.db.conn.execute("DELETE FROM notifications")
        for k in ("amma", "ravi", "priya"):
            reg.set_language(family[k], "hi")
        reg.report_sim_change(family["bank"], AMMA)
        reg.invite_guardian(family["amma"], PRIYA)
        rows = reg.db.all("SELECT kind, title, body FROM notifications WHERE recipient_type='user'")
        bad = {r["kind"]: _english_left(r["title"] + " " + r["body"]) for r in rows}
        assert not {k: v for k, v in bad.items() if v}, bad

    def test_english_speakers_are_unchanged(self, reg, family):
        reg.check(family["bank"], AMMA, "t1", 20_000 * R, "known@upi")
        r = reg.db.one("SELECT title FROM notifications WHERE kind='approval_needed' AND channel='inapp'")
        assert r["title"] == "Approve payment?"

    def test_sms_goes_out_in_hindi(self, reg, family, clock):
        from guardian_registry.notify import Dispatcher
        reg.set_language(family["ravi"], "hi")
        sms = LogSmsSender()
        d = Dispatcher(reg.db, clock, sms=sms, whatsapp=None, push=None)
        d.run_once()
        sms.sent.clear()
        reg.check(family["bank"], AMMA, "t1", 20_000 * R, "known@upi")
        d.run_once()
        to_ravi = [t for to, t in sms.sent if to.endswith(RAVI[-6:])]
        assert to_ravi and to_ravi[0].startswith("भुगतान मंज़ूर करें?")


# ------------------------------------------------------------------ sign-in code
def test_code_sms_in_hindi(reg, family, clock):
    sms = LogSmsSender()
    reg.request_otp("+919811122233", sms, "hi")                       # new number, app says Hindi
    assert sms.sent[-1][1].startswith("Guardian Registry कोड:")
    reg.set_language(family["amma"], "hi")
    clock.advance(seconds=OTP_RESEND_SECONDS + 1)
    reg.request_otp(AMMA, sms)                                         # enrolled Hindi speaker
    assert "मिनट तक मान्य" in sms.sent[-1][1]


def test_msg91_uses_hindi_dlt_templates_when_registered():
    seen = []

    def handler(request):
        seen.append(json.loads(request.content)["template_id"])
        return httpx.Response(200, json={"type": "success"})
    s = Msg91Sms("k", "otp-en", "alert-en", client=httpx.Client(transport=httpx.MockTransport(handler)),
                 templates_hi=("otp-hi", "alert-hi"))
    s.send_otp("+919800000001", "123456", 5, "hi")
    s.send_alert_in("+919800000001", "भुगतान", "...", "hi")
    s.send_otp("+919800000001", "123456", 5, "en")
    assert seen == ["otp-hi", "alert-hi", "otp-en"]


def test_whatsapp_uses_hindi_only_when_meta_approved_it():
    langs = []

    def handler(request):
        langs.append(json.loads(request.content)["template"]["language"]["code"])
        return httpx.Response(200, json={})
    client = httpx.Client(transport=httpx.MockTransport(handler))
    MetaWhatsApp("1", "t", client=client, approved_languages=("en", "hi")).send_in("+919800000001", "a", "b", "hi")
    MetaWhatsApp("1", "t", client=client).send_in("+919800000001", "a", "b", "hi")
    assert langs == ["hi", "en"]


# ------------------------------------------------------------------ API
def test_api_language_and_hindi_errors(reg):
    from guardian_registry.api import create_app
    with TestClient(create_app(reg, run_worker=False)) as c:
        out = c.post("/v1/auth/otp", json={"mobile": "+919822233344", "language": "hi"})
        assert out.status_code == 202
        code = reg.db.one("SELECT 1 FROM otps")  # noqa: F841  (the code went out in Hindi; see test above)
        r = c.post("/v1/auth/otp", json={"mobile": "+919822233344"}, headers={"Accept-Language": "hi-IN,hi"})
        assert r.status_code == 429 and r.json()["detail"].startswith("दूसरा कोड माँगने से पहले")
        r = c.post("/v1/auth/otp", json={"mobile": "+919822233344"})
        assert r.json()["detail"].startswith("wait ")                 # English without the header
        r = c.get("/v1/me", headers={"Accept-Language": "hi"})
        assert r.status_code == 401 and "फिर से साइन इन" in r.json()["detail"]
        uid, tok = reg.register_user("+919833344455", "Lang Person")
        h = {"Authorization": f"Bearer {tok}"}
        assert c.put("/v1/me/language", headers=h, json={"language": "hi"}).json()["language"] == "hi"
        assert c.get("/v1/me", headers=h).json()["language"] == "hi"
        assert c.put("/v1/me/language", headers=h, json={"language": "fr"}).status_code == 422
