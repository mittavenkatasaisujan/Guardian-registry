"""Direct connections to real message providers. Each needs only the provider's credentials.

    SMS       Twilio (GR_SMS_PROVIDER=twilio) or MSG91 (GR_SMS_PROVIDER=msg91). Indian SMS
              must match a DLT-registered template, so MSG91 sends template ids plus
              variables, never free text: one template for codes, one for alerts.
    WhatsApp  Meta's WhatsApp Cloud API (GR_WHATSAPP_PROVIDER=meta) with an approved
              template whose body has two variables: {{1}} = title, {{2}} = text.
    Push      Firebase Cloud Messaging HTTP v1 (service-account OAuth) for Android, and
              Apple Push Notification service (token-based .p8 auth, HTTP/2) for iOS.
              GR_PUSH_PROVIDER=direct picks FCM or APNs by each install's platform.

A push token the provider says is dead (app uninstalled, token rotated) raises DeadToken;
the dispatcher deletes it so it is never tried again.

The generic HTTP senders in notify.py still work for any other provider behind an adapter.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time

import httpx
import jwt

from .notify import PushSender, SmsSender, WhatsAppSender
from .security import log_safe, mask_mobile

log = logging.getLogger(__name__)


class DeadToken(Exception):
    """The provider says this push token will never work again."""


class ProviderError(RuntimeError):
    pass


def _need(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise RuntimeError(f"{name} is required for the configured provider")
    return v


def _read(path_or_value: str) -> str:
    if os.path.exists(path_or_value):
        with open(path_or_value, encoding="utf-8") as f:
            return f.read()
    return path_or_value


def _check(r: httpx.Response, what: str) -> None:
    if r.status_code >= 300:
        raise ProviderError(f"{what} returned HTTP {r.status_code}: {r.text[:300]}")


# ------------------------------------------------------------------ SMS
class TwilioSms(SmsSender):
    def __init__(self, account_sid: str, auth_token: str, sender: str, client: httpx.Client | None = None):
        """sender: a Messaging Service SID (MG...) or a phone number / sender id."""
        self.sid, self.auth, self.sender = account_sid, auth_token, sender
        self.client = client or httpx.Client(timeout=10)

    def send(self, to: str, text: str) -> None:
        data = {"To": to, "Body": text}
        data["MessagingServiceSid" if self.sender.startswith("MG") else "From"] = self.sender
        r = self.client.post(f"https://api.twilio.com/2010-04-01/Accounts/{self.sid}/Messages.json",
                             data=data, auth=(self.sid, self.auth))
        _check(r, "Twilio")


class TwilioVerifySms(SmsSender):
    """Sign-in codes through Twilio Verify: Twilio makes, sends and checks the code. It works on
    a free Twilio trial, which can only send Twilio's own wording, not ours. Free-form alert SMS
    isn't possible there, so alerts are logged and skipped; people still get them in the app and
    by push. The registry keeps its own limits (resend wait, sends per window, attempts, expiry)."""

    checks_codes = True
    LOCALES = {"en", "hi"}   # Verify locales we have checked; others get Twilio's English

    def __init__(self, account_sid: str, auth_token: str, service_sid: str, client: httpx.Client | None = None):
        self.sid, self.auth, self.service = account_sid, auth_token, service_sid
        self.client = client or httpx.Client(timeout=10)
        self.base = f"https://verify.twilio.com/v2/Services/{service_sid}"

    def send(self, to: str, text: str) -> None:
        log.info("SMS alert to %s skipped: Twilio Verify sends sign-in codes only (alerts go in-app and by push)",
                 log_safe(mask_mobile(to)))

    def send_otp(self, to: str, code: str, minutes: int, language: str = "en") -> None:
        data = {"To": to, "Channel": "sms"}
        if language in self.LOCALES:
            data["Locale"] = language
        r = self.client.post(f"{self.base}/Verifications", data=data, auth=(self.sid, self.auth))
        _check(r, "Twilio Verify")

    def check_code(self, to: str, code: str) -> bool:
        r = self.client.post(f"{self.base}/VerificationCheck", data={"To": to, "Code": code},
                             auth=(self.sid, self.auth))
        if r.status_code == 404:   # nothing pending for this number: expired, used or never sent
            return False
        _check(r, "Twilio Verify")
        return r.json().get("status") == "approved"


class Msg91Sms(SmsSender):
    """MSG91 Flow API. Templates (registered on DLT, then in MSG91):
        OTP template   with variable  ##otp##      e.g. "Your Guardian Registry code is ##otp##. ..."
        alert template with variable  ##title##    e.g. "Guardian Registry: ##title##. Open the app to respond."
    DLT variables are short, so alerts carry only the title; the full text is in the app."""

    URL = "https://control.msg91.com/api/v5/flow"

    def __init__(self, authkey: str, otp_template: str, alert_template: str, client: httpx.Client | None = None,
                 templates_hi: tuple[str, str] | None = None):
        """templates_hi: (OTP, alert) DLT template ids registered in Hindi; without them Hindi
        speakers get the English templates (the alert title variable is still in Hindi)."""
        self.authkey, self.otp_template, self.alert_template = authkey, otp_template, alert_template
        self.templates_hi = templates_hi
        self.client = client or httpx.Client(timeout=10)

    def _flow(self, template: str, to: str, variables: dict) -> None:
        r = self.client.post(self.URL, headers={"authkey": self.authkey, "accept": "application/json"},
                             json={"template_id": template, "short_url": "0",
                                   "recipients": [{"mobiles": to.lstrip("+"), **variables}]})
        _check(r, "MSG91")
        body = r.json() if r.content else {}
        if isinstance(body, dict) and body.get("type") == "error":
            raise ProviderError(f"MSG91 error: {body.get('message')}")

    def send(self, to: str, text: str) -> None:
        self._flow(self.alert_template, to, {"title": text[:30]})

    def send_otp(self, to: str, code: str, minutes: int, language: str = "en") -> None:
        tpl = self.templates_hi[0] if language == "hi" and self.templates_hi else self.otp_template
        self._flow(tpl, to, {"otp": code})

    def send_alert(self, to: str, title: str, body: str) -> None:
        self._flow(self.alert_template, to, {"title": title[:30]})

    def send_alert_in(self, to: str, title: str, body: str, language: str) -> None:
        tpl = self.templates_hi[1] if language == "hi" and self.templates_hi else self.alert_template
        self._flow(tpl, to, {"title": title[:30]})


# ------------------------------------------------------------------ WhatsApp
class MetaWhatsApp(WhatsAppSender):
    def __init__(self, phone_number_id: str, access_token: str, template: str = "guardian_alert",
                 language: str = "en", api_version: str = "v21.0", client: httpx.Client | None = None,
                 approved_languages: tuple[str, ...] = ("en",)):
        """approved_languages: the template languages Meta approved (GR_WHATSAPP_TEMPLATE_LANGUAGES).
        A person's language is used when it is one of them; otherwise `language`."""
        self.url = f"https://graph.facebook.com/{api_version}/{phone_number_id}/messages"
        self.token, self.template, self.language = access_token, template, language
        self.approved = tuple(approved_languages)
        self.client = client or httpx.Client(timeout=10)

    def send_in(self, to: str, title: str, body: str, language: str) -> None:
        self._send(to, title, body, language if language in self.approved else self.language)

    def send(self, to: str, title: str, body: str) -> None:
        self._send(to, title, body, self.language)

    def _send(self, to: str, title: str, body: str, language: str) -> None:
        payload = {
            "messaging_product": "whatsapp", "to": to.lstrip("+"), "type": "template",
            "template": {"name": self.template, "language": {"code": language},
                         "components": [{"type": "body", "parameters": [
                             {"type": "text", "text": title[:60]}, {"type": "text", "text": body[:900]}]}]},
        }
        r = self.client.post(self.url, json=payload, headers={"Authorization": f"Bearer {self.token}"})
        _check(r, "WhatsApp Cloud API")


# ------------------------------------------------------------------ push: FCM
class FcmPush(PushSender):
    SCOPE = "https://www.googleapis.com/auth/firebase.messaging"

    def __init__(self, service_account: dict, client: httpx.Client | None = None, now=time.time):
        for k in ("client_email", "private_key", "project_id"):
            if not service_account.get(k):
                raise RuntimeError(f"FCM service account JSON is missing {k}")
        self.sa = service_account
        self.token_uri = service_account.get("token_uri") or "https://oauth2.googleapis.com/token"
        self.client, self.now = client or httpx.Client(timeout=10), now
        self._access: tuple[str, float] | None = None
        self._lock = threading.Lock()

    def access_token(self) -> str:
        with self._lock:
            if self._access and self._access[1] - 60 > self.now():
                return self._access[0]
            iat = int(self.now())
            assertion = jwt.encode({"iss": self.sa["client_email"], "scope": self.SCOPE, "aud": self.token_uri,
                                    "iat": iat, "exp": iat + 3600}, self.sa["private_key"], algorithm="RS256",
                                   headers={"kid": self.sa.get("private_key_id")} if self.sa.get("private_key_id") else None)
            r = self.client.post(self.token_uri, data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": assertion})
            _check(r, "Google OAuth")
            body = r.json()
            self._access = (body["access_token"], self.now() + int(body.get("expires_in", 3600)))
            return self._access[0]

    def send(self, token: str, platform: str, title: str, body: str, data: dict) -> None:
        msg = {"message": {"token": token, "notification": {"title": title, "body": body},
                           "data": {k: str(v) for k, v in data.items()},
                           "android": {"priority": "HIGH"},
                           "apns": {"headers": {"apns-priority": "10"}}}}
        r = self.client.post(f"https://fcm.googleapis.com/v1/projects/{self.sa['project_id']}/messages:send",
                             json=msg, headers={"Authorization": f"Bearer {self.access_token()}"})
        if r.status_code in (400, 404):
            err = (r.json() if r.content else {}).get("error", {})
            codes = {d.get("errorCode") for d in err.get("details", []) if isinstance(d, dict)}
            if "UNREGISTERED" in codes or err.get("status") == "NOT_FOUND":
                raise DeadToken("FCM: token is no longer registered")
        _check(r, "FCM")


# ------------------------------------------------------------------ push: APNs
class ApnsPush(PushSender):
    HOSTS = {"production": "https://api.push.apple.com", "sandbox": "https://api.sandbox.push.apple.com"}
    JWT_REFRESH = 45 * 60  # Apple: refresh no more than every 20 min, no less than every 60

    def __init__(self, p8_key: str, key_id: str, team_id: str, topic: str, environment: str = "production",
                 client: httpx.Client | None = None, now=time.time):
        if environment not in self.HOSTS:
            raise RuntimeError("GR_APNS_ENV must be production or sandbox")
        self.key, self.key_id, self.team_id, self.topic = p8_key, key_id, team_id, topic
        self.host, self.now = self.HOSTS[environment], now
        self.client = client or httpx.Client(http2=True, timeout=10)
        self._jwt: tuple[str, float] | None = None
        self._lock = threading.Lock()

    def provider_token(self) -> str:
        with self._lock:
            if self._jwt and self.now() - self._jwt[1] < self.JWT_REFRESH:
                return self._jwt[0]
            iat = int(self.now())
            tok = jwt.encode({"iss": self.team_id, "iat": iat}, self.key, algorithm="ES256",
                             headers={"kid": self.key_id})
            self._jwt = (tok, iat)
            return tok

    def send(self, token: str, platform: str, title: str, body: str, data: dict) -> None:
        payload = {"aps": {"alert": {"title": title, "body": body}, "sound": "default"},
                   **{k: v for k, v in data.items() if k != "aps"}}
        r = self.client.post(f"{self.host}/3/device/{token}", json=payload, headers={
            "authorization": f"bearer {self.provider_token()}", "apns-topic": self.topic,
            "apns-push-type": "alert", "apns-priority": "10"})
        if r.status_code == 410:
            raise DeadToken("APNs: device token is no longer active")
        if r.status_code == 400:
            reason = (r.json() if r.content else {}).get("reason")
            if reason in ("BadDeviceToken", "DeviceTokenNotForTopic"):
                raise DeadToken(f"APNs: {reason}")
        _check(r, "APNs")


class PlatformPush(PushSender):
    """Android installs -> FCM, iOS installs -> APNs (or FCM if APNs isn't configured)."""

    def __init__(self, fcm: FcmPush | None, apns: ApnsPush | None):
        if not fcm and not apns:
            raise RuntimeError("direct push needs GR_FCM_SERVICE_ACCOUNT and/or GR_APNS_*")
        self.fcm, self.apns = fcm, apns

    def send(self, token: str, platform: str, title: str, body: str, data: dict) -> None:
        target = self.apns if platform == "ios" and self.apns else self.fcm
        if target is None:
            raise ProviderError(f"no push provider configured for {platform} installs")
        target.send(token, platform, title, body, data)


# ------------------------------------------------------------------ from the environment
def sms_from_env() -> SmsSender | None:
    p = os.environ.get("GR_SMS_PROVIDER", "").strip().lower()
    if not p:
        return None
    if p == "twilio":
        return TwilioSms(_need("GR_TWILIO_ACCOUNT_SID"), _need("GR_TWILIO_AUTH_TOKEN"), _need("GR_TWILIO_FROM"))
    if p == "twilio_verify":
        return TwilioVerifySms(_need("GR_TWILIO_ACCOUNT_SID"), _need("GR_TWILIO_AUTH_TOKEN"),
                               _need("GR_TWILIO_VERIFY_SERVICE"))
    if p == "msg91":
        hi = (os.environ.get("GR_MSG91_OTP_TEMPLATE_HI"), os.environ.get("GR_MSG91_ALERT_TEMPLATE_HI"))
        return Msg91Sms(_need("GR_MSG91_AUTHKEY"), _need("GR_MSG91_OTP_TEMPLATE"), _need("GR_MSG91_ALERT_TEMPLATE"),
                        templates_hi=hi if all(hi) else None)
    raise RuntimeError("GR_SMS_PROVIDER must be twilio, twilio_verify or msg91")


def whatsapp_from_env() -> WhatsAppSender | None:
    p = os.environ.get("GR_WHATSAPP_PROVIDER", "").strip().lower()
    if not p:
        return None
    if p == "meta":
        return MetaWhatsApp(_need("GR_WHATSAPP_PHONE_NUMBER_ID"), _need("GR_WHATSAPP_ACCESS_TOKEN"),
                            os.environ.get("GR_WHATSAPP_TEMPLATE", "guardian_alert"),
                            os.environ.get("GR_WHATSAPP_LANGUAGE", "en"),
                            approved_languages=tuple(x.strip() for x in os.environ.get(
                                "GR_WHATSAPP_TEMPLATE_LANGUAGES", "en").split(",") if x.strip()))
    raise RuntimeError("GR_WHATSAPP_PROVIDER must be meta")


def push_from_env() -> PushSender | None:
    p = os.environ.get("GR_PUSH_PROVIDER", "").strip().lower()
    if not p:
        return None
    if p != "direct":
        raise RuntimeError("GR_PUSH_PROVIDER must be direct")
    fcm = apns = None
    if os.environ.get("GR_FCM_SERVICE_ACCOUNT"):
        fcm = FcmPush(json.loads(_read(os.environ["GR_FCM_SERVICE_ACCOUNT"])))
    if os.environ.get("GR_APNS_KEY"):
        apns = ApnsPush(_read(os.environ["GR_APNS_KEY"]), _need("GR_APNS_KEY_ID"), _need("GR_APNS_TEAM_ID"),
                        _need("GR_APNS_TOPIC"), os.environ.get("GR_APNS_ENV", "production"))
    return PlatformPush(fcm, apns)
