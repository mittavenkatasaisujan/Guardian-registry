"""Direct provider connections: Twilio, MSG91, WhatsApp Cloud API, FCM v1, APNs."""

import json
import time
from urllib.parse import parse_qs

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from guardian_registry import providers as P
from guardian_registry.notify import Dispatcher, LogSmsSender, sms_sender_from_env

from .conftest import AMMA, R

T0 = int(time.time())


class Recorder:
    def __init__(self, *responses):
        self.requests, self.responses = [], list(responses)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        r = self.responses.pop(0) if self.responses else httpx.Response(200, json={})
        return r(request) if callable(r) else r

    def client(self):
        return httpx.Client(transport=httpx.MockTransport(self))


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


# ------------------------------------------------------------------ SMS
def test_twilio_with_messaging_service():
    rec = Recorder(httpx.Response(201, json={"sid": "SM1"}))
    P.TwilioSms("AC123", "secret", "MG999", client=rec.client()).send("+919800000001", "hello")
    req = rec.requests[0]
    assert str(req.url) == "https://api.twilio.com/2010-04-01/Accounts/AC123/Messages.json"
    form = parse_qs(req.content.decode())
    assert form == {"To": ["+919800000001"], "Body": ["hello"], "MessagingServiceSid": ["MG999"]}
    assert req.headers["authorization"].startswith("Basic ")


def test_twilio_error_is_raised():
    rec = Recorder(httpx.Response(400, json={"message": "invalid To"}))
    with pytest.raises(P.ProviderError, match="400"):
        P.TwilioSms("AC1", "s", "+15005550006", client=rec.client()).send("x", "y")


def test_msg91_uses_dlt_templates():
    rec = Recorder(httpx.Response(200, json={"type": "success"}), httpx.Response(200, json={"type": "success"}))
    s = P.Msg91Sms("authk", "tpl-otp", "tpl-alert", client=rec.client())
    s.send_otp("+919800000001", "123456", 10)
    s.send_alert("+919800000001", "Approve payment?", "a long body the DLT template can't carry")
    otp, alert = (json.loads(r.content) for r in rec.requests)
    assert rec.requests[0].headers["authkey"] == "authk"
    assert otp == {"template_id": "tpl-otp", "short_url": "0", "recipients": [{"mobiles": "919800000001",
                                                                                 "otp": "123456"}]}
    assert alert["template_id"] == "tpl-alert" and alert["recipients"][0]["title"] == "Approve payment?"


def test_msg91_error_body():
    rec = Recorder(httpx.Response(200, json={"type": "error", "message": "template not approved"}))
    with pytest.raises(P.ProviderError, match="template not approved"):
        P.Msg91Sms("k", "a", "b", client=rec.client()).send_otp("+91", "1", 1)


def test_otp_goes_through_the_template(reg):
    rec = Recorder(httpx.Response(200, json={"type": "success"}))
    code = reg.request_otp(AMMA, P.Msg91Sms("k", "tpl-otp", "tpl-alert", client=rec.client()))
    assert json.loads(rec.requests[0].content)["recipients"][0]["otp"] == code


def test_env_selection(monkeypatch):
    monkeypatch.setenv("GR_SMS_PROVIDER", "twilio")
    with pytest.raises(RuntimeError, match="GR_TWILIO_ACCOUNT_SID"):
        sms_sender_from_env()
    for k, v in {"GR_TWILIO_ACCOUNT_SID": "AC1", "GR_TWILIO_AUTH_TOKEN": "t", "GR_TWILIO_FROM": "MG1"}.items():
        monkeypatch.setenv(k, v)
    assert isinstance(sms_sender_from_env(), P.TwilioSms)
    monkeypatch.setenv("GR_SMS_PROVIDER", "carrier-pigeon")
    with pytest.raises(RuntimeError):
        sms_sender_from_env()
    monkeypatch.delenv("GR_SMS_PROVIDER")
    assert isinstance(sms_sender_from_env(), LogSmsSender)


# ------------------------------------------------------------------ WhatsApp
def test_whatsapp_cloud_template():
    rec = Recorder(httpx.Response(200, json={"messages": [{"id": "wamid"}]}))
    P.MetaWhatsApp("10987", "EAAG", client=rec.client()).send("+919800000001", "Approve payment?", "₹20,000 to x")
    req = rec.requests[0]
    assert str(req.url) == "https://graph.facebook.com/v21.0/10987/messages"
    assert req.headers["authorization"] == "Bearer EAAG"
    body = json.loads(req.content)
    assert body["to"] == "919800000001" and body["type"] == "template"
    assert body["template"]["name"] == "guardian_alert"
    assert [p["text"] for p in body["template"]["components"][0]["parameters"]] == ["Approve payment?", "₹20,000 to x"]


# ------------------------------------------------------------------ FCM
@pytest.fixture
def service_account():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, {"client_email": "gr@proj.iam.gserviceaccount.com", "private_key": _pem(key),
                 "private_key_id": "kid1", "project_id": "guardian-proj",
                 "token_uri": "https://oauth2.googleapis.com/token"}


def test_fcm_oauth_and_send(service_account):
    key, sa = service_account
    rec = Recorder(httpx.Response(200, json={"access_token": "ya29.x", "expires_in": 3599}),
                   httpx.Response(200, json={"name": "projects/guardian-proj/messages/1"}),
                   httpx.Response(200, json={"name": "projects/guardian-proj/messages/2"}))
    fcm = P.FcmPush(sa, client=rec.client(), now=lambda: T0)
    fcm.send("tok-A", "android", "Approve payment?", "body", {"kind": "approval_needed", "n": 1})
    fcm.send("tok-B", "android", "t", "b", {})
    token_req, send_req, _ = rec.requests
    grant = parse_qs(token_req.content.decode())
    claims = jwt.decode(grant["assertion"][0], key.public_key(), algorithms=["RS256"],
                        audience="https://oauth2.googleapis.com/token")
    assert claims["iss"] == sa["client_email"] and claims["scope"].endswith("firebase.messaging")
    assert str(send_req.url) == "https://fcm.googleapis.com/v1/projects/guardian-proj/messages:send"
    assert send_req.headers["authorization"] == "Bearer ya29.x"
    msg = json.loads(send_req.content)["message"]
    assert msg["token"] == "tok-A" and msg["data"] == {"kind": "approval_needed", "n": "1"}
    assert len(rec.requests) == 3  # access token reused for the second send


def test_fcm_unregistered_token_is_dead(service_account):
    _, sa = service_account
    rec = Recorder(httpx.Response(200, json={"access_token": "a", "expires_in": 3600}),
                   httpx.Response(404, json={"error": {"code": 404, "status": "NOT_FOUND", "details": [
                       {"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": "UNREGISTERED"}]}}))
    with pytest.raises(P.DeadToken):
        P.FcmPush(sa, client=rec.client()).send("t", "android", "x", "y", {})


def test_fcm_server_error_is_retryable(service_account):
    _, sa = service_account
    rec = Recorder(httpx.Response(200, json={"access_token": "a", "expires_in": 3600}),
                   httpx.Response(503, json={"error": {"status": "UNAVAILABLE"}}))
    with pytest.raises(P.ProviderError):
        P.FcmPush(sa, client=rec.client()).send("t", "android", "x", "y", {})


# ------------------------------------------------------------------ APNs
@pytest.fixture
def p8():
    key = ec.generate_private_key(ec.SECP256R1())
    return key, _pem(key)


def test_apns_request(p8):
    key, pem = p8
    rec = Recorder(httpx.Response(200))
    apns = P.ApnsPush(pem, "KEY123", "TEAM456", "in.guardianregistry.app", "sandbox", client=rec.client(),
                      now=lambda: T0)
    apns.send("abcd" * 16, "ios", "Approve payment?", "body", {"kind": "approval_needed"})
    req = rec.requests[0]
    assert str(req.url) == "https://api.sandbox.push.apple.com/3/device/" + "abcd" * 16
    assert req.headers["apns-topic"] == "in.guardianregistry.app" and req.headers["apns-push-type"] == "alert"
    tok = req.headers["authorization"].split(" ", 1)[1]
    assert jwt.get_unverified_header(tok)["kid"] == "KEY123"
    assert jwt.decode(tok, key.public_key(), algorithms=["ES256"])["iss"] == "TEAM456"
    assert json.loads(req.content)["aps"]["alert"] == {"title": "Approve payment?", "body": "body"}


def test_apns_provider_token_is_reused_then_refreshed(p8):
    _, pem = p8
    t = [1_800_000_000]
    apns = P.ApnsPush(pem, "K", "T", "b", client=Recorder().client(), now=lambda: t[0])
    first = apns.provider_token()
    t[0] += 60
    assert apns.provider_token() == first
    t[0] += P.ApnsPush.JWT_REFRESH
    assert apns.provider_token() != first


@pytest.mark.parametrize("resp", [httpx.Response(410, json={"reason": "Unregistered"}),
                                  httpx.Response(400, json={"reason": "BadDeviceToken"})])
def test_apns_dead_tokens(p8, resp):
    with pytest.raises(P.DeadToken):
        P.ApnsPush(p8[1], "K", "T", "b", client=Recorder(resp).client()).send("t", "ios", "x", "y", {})


def test_platform_routing(p8, service_account):
    sent = []

    class Fake:
        def __init__(self, name):
            self.name = name

        def send(self, token, platform, *a):
            sent.append((self.name, token))

    P.PlatformPush(Fake("fcm"), Fake("apns")).send("i", "ios", "t", "b", {})
    P.PlatformPush(Fake("fcm"), Fake("apns")).send("a", "android", "t", "b", {})
    P.PlatformPush(Fake("fcm"), None).send("i2", "ios", "t", "b", {})  # FCM can reach iOS too
    assert sent == [("apns", "i"), ("fcm", "a"), ("fcm", "i2")]
    with pytest.raises(P.ProviderError):
        P.PlatformPush(None, Fake("apns")).send("a", "android", "t", "b", {})


# ------------------------------------------------------------------ dispatcher + dead tokens
def test_dead_token_is_deleted_and_other_devices_still_get_it(reg, family, clock):
    sent = []

    class Push:
        def send(self, token, platform, title, body, data):
            if token == "uninstalled-token":
                raise P.DeadToken("gone")
            sent.append(token)

    reg.add_push_token(family["ravi"], "uninstalled-token", "android")
    reg.add_push_token(family["ravi"], "live-ios-token", "ios")
    d = Dispatcher(reg.db, clock, sms=LogSmsSender(), whatsapp=None, push=Push())
    d.run_once()
    reg.check(family["bank"], AMMA, "t1", 20_000 * R, "known@upi")
    d.run_once()
    assert "live-ios-token" in sent
    assert [x["platform"] for x in reg.alert_settings(family["ravi"])["push_devices"]] == ["ios"]
    assert not reg.db.one("SELECT 1 FROM notifications WHERE channel='push' AND status='pending'")
