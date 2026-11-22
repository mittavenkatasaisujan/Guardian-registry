import sqlite3

import pytest

from guardian_registry.db import SCHEMA_V1, Database
from guardian_registry.errors import Invalid, NotFound, TooMany, Unauthorized
from guardian_registry.notify import LogSmsSender
from guardian_registry.presets import PRESETS
from guardian_registry.security import check_production_config, decrypt_mobile, secret_hash
from guardian_registry.service import (
    KEY_ROTATION_GRACE_HOURS, OTP_MAX_ATTEMPTS, OTP_MAX_SENDS_PER_WINDOW, OTP_RESEND_SECONDS,
    OTP_TTL_MINUTES, OTP_WINDOW_MINUTES, SESSION_DAYS, Registry,
)

from .conftest import AMMA, R


@pytest.fixture
def sms():
    return LogSmsSender()


class TestOtp:
    def test_enrol_with_otp(self, reg, sms):
        code = reg.request_otp(AMMA, sms)
        assert sms.sent[-1] == ("+91" + AMMA, sms.sent[-1][1]) and code in sms.sent[-1][1]
        out = reg.verify_otp(AMMA, code, display_name="Amma")
        assert out["new_user"] is True and reg.user_by_token(out["token"]) == out["user_id"]

    def test_login_existing_user(self, reg, sms):
        uid, _ = reg.register_user(AMMA, "Amma")
        out = reg.verify_otp(AMMA, reg.request_otp(AMMA, sms))
        assert out == {"user_id": uid, "token": out["token"], "new_user": False}

    def test_new_number_needs_name(self, reg, sms):
        code = reg.request_otp(AMMA, sms)
        with pytest.raises(Invalid):
            reg.verify_otp(AMMA, code)

    def test_code_is_single_use(self, reg, sms):
        code = reg.request_otp(AMMA, sms)
        reg.verify_otp(AMMA, code, "Amma")
        with pytest.raises(Unauthorized):
            reg.verify_otp(AMMA, code)

    def test_wrong_code_and_lockout(self, reg, sms):
        code = reg.request_otp(AMMA, sms)
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(OTP_MAX_ATTEMPTS):
            with pytest.raises(Unauthorized):
                reg.verify_otp(AMMA, wrong, "Amma")
        with pytest.raises(Unauthorized, match="too many"):
            reg.verify_otp(AMMA, code, "Amma")   # even the right code is refused now

    def test_expiry(self, reg, sms, clock):
        code = reg.request_otp(AMMA, sms)
        clock.advance(minutes=OTP_TTL_MINUTES)
        with pytest.raises(Unauthorized, match="expired"):
            reg.verify_otp(AMMA, code, "Amma")

    def test_resend_cooldown_and_window_cap(self, reg, sms, clock):
        reg.request_otp(AMMA, sms)
        with pytest.raises(TooMany):
            reg.request_otp(AMMA, sms)
        for _ in range(OTP_MAX_SENDS_PER_WINDOW - 1):
            clock.advance(seconds=OTP_RESEND_SECONDS)
            reg.request_otp(AMMA, sms)
        clock.advance(seconds=OTP_RESEND_SECONDS)
        with pytest.raises(TooMany):
            reg.request_otp(AMMA, sms)
        clock.advance(minutes=OTP_WINDOW_MINUTES)
        reg.request_otp(AMMA, sms)

    def test_new_code_replaces_old(self, reg, sms, clock):
        old = reg.request_otp(AMMA, sms)
        clock.advance(seconds=OTP_RESEND_SECONDS)
        new = reg.request_otp(AMMA, sms)
        if old != new:
            with pytest.raises(Unauthorized):
                reg.verify_otp(AMMA, old, "Amma")
        assert reg.verify_otp(AMMA, new, "Amma")["new_user"]

    def test_code_not_stored_in_clear(self, reg, sms):
        code = reg.request_otp(AMMA, sms)
        dump = "\n".join(reg.db.conn.iterdump())
        assert f"'{code}'" not in dump and AMMA not in dump

    def test_invalid_number(self, reg, sms):
        with pytest.raises(Invalid):
            reg.request_otp("123", sms)


class TestSessions:
    def test_expiry(self, reg, clock):
        _, token = reg.register_user(AMMA, "Amma")
        clock.advance(days=SESSION_DAYS)
        assert reg.user_by_token(token) is None

    def test_logout_one_and_everywhere(self, reg, sms, clock):
        uid, t1 = reg.register_user(AMMA, "Amma")
        t2 = reg.verify_otp(AMMA, reg.request_otp(AMMA, sms))["token"]
        reg.logout(t1)
        assert reg.user_by_token(t1) is None and reg.user_by_token(t2) == uid
        clock.advance(seconds=OTP_RESEND_SECONDS)
        t3 = reg.verify_otp(AMMA, reg.request_otp(AMMA, sms))["token"]
        reg.logout(t2, everywhere=True)
        assert reg.user_by_token(t2) is None and reg.user_by_token(t3) is None

    def test_mobile_encrypted_and_recoverable(self, reg):
        uid, _ = reg.register_user("+91 " + AMMA, "Amma")
        enc = reg.db.one("SELECT mobile_enc FROM users WHERE id=?", (uid,))["mobile_enc"]
        assert AMMA not in enc and decrypt_mobile(enc) == "+91" + AMMA


class TestKeyRotation:
    def test_grace_period(self, reg, clock):
        pid, old = reg.register_participant("Bank")
        new = reg.rotate_participant_key(pid)["api_key"]
        assert reg.participant_by_key(old) == pid and reg.participant_by_key(new) == pid
        clock.advance(hours=KEY_ROTATION_GRACE_HOURS)
        assert reg.participant_by_key(old) is None and reg.participant_by_key(new) == pid

    def test_second_rotation_kills_first_key(self, reg):
        pid, k1 = reg.register_participant("Bank")
        k2 = reg.rotate_participant_key(pid)["api_key"]
        reg.rotate_participant_key(pid)
        assert reg.participant_by_key(k1) is None and reg.participant_by_key(k2) == pid


class TestPresets:
    def test_apply_on_fresh_user_applies_now(self, reg):
        uid, _ = reg.register_user(AMMA, "Amma")
        out = reg.apply_preset(uid, "senior_with_guardian")
        assert out["held"] is None
        assert reg.get_rules(uid).approval_threshold == 10_000 * R

    def test_looser_preset_is_held(self, reg):
        uid, _ = reg.register_user(AMMA, "Amma")
        reg.apply_preset(uid, "strict")
        out = reg.apply_preset(uid, "rbi_high_value_delay")  # raises new-payee threshold, shorter wait
        assert out["held"] is not None
        assert reg.get_rules(uid).new_payee_delay_threshold == 2_000 * R

    def test_unknown_preset(self, reg):
        uid, _ = reg.register_user(AMMA, "Amma")
        with pytest.raises(NotFound):
            reg.apply_preset(uid, "yolo")

    @pytest.mark.parametrize("name", list(PRESETS))
    def test_presets_are_valid_rules(self, reg, name):
        uid, _ = reg.register_user(AMMA, "Amma")
        reg.apply_preset(uid, name)


class TestMigration:
    def test_v1_database_upgrades_with_sessions_kept(self, tmp_path, clock):
        path = str(tmp_path / "old.db")
        raw = sqlite3.connect(path)
        raw.executescript(SCHEMA_V1 + "\nPRAGMA user_version = 1;")
        raw.execute("INSERT INTO users VALUES ('usr_old','mh','Old User',?, '2026-01-01T00:00:00+00:00')",
                    (secret_hash("old-token"),))
        raw.execute("INSERT INTO rules VALUES ('usr_old','{}','2026-01-01T00:00:00+00:00')")
        raw.commit()
        raw.close()

        reg = Registry(Database(path), clock)
        assert reg.db.conn.execute("PRAGMA user_version").fetchone()[0] == 2
        assert reg.user_by_token("old-token") == "usr_old"
        assert reg.db.conn.execute("PRAGMA foreign_key_check").fetchall() == []
        reg.db.close()
        assert Database(path).migrate() == 2  # re-opening is a no-op


class TestProductionConfig:
    def test_refuses_dev_secrets(self, monkeypatch):
        monkeypatch.setenv("GR_ENV", "production")
        monkeypatch.delenv("GR_PEPPER", raising=False)
        with pytest.raises(RuntimeError, match="GR_PEPPER"):
            check_production_config()

    def test_refuses_otp_echo(self, monkeypatch):
        monkeypatch.setenv("GR_ENV", "production")
        monkeypatch.setenv("GR_PEPPER", "p")
        monkeypatch.setenv("GR_DATA_KEY", "x" * 43 + "=")
        monkeypatch.setenv("GR_OTP_DEV_ECHO", "1")
        with pytest.raises(RuntimeError, match="OTP"):
            check_production_config()

    def test_ok_when_configured(self, monkeypatch):
        monkeypatch.setenv("GR_ENV", "production")
        monkeypatch.setenv("GR_PEPPER", "p")
        monkeypatch.setenv("GR_DATA_KEY", "x" * 43 + "=")
        monkeypatch.delenv("GR_OTP_DEV_ECHO", raising=False)
        check_production_config()
