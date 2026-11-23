"""Secrets from files, and rotating the data key."""

import json

import pytest
from cryptography.fernet import Fernet

from guardian_registry import secrets_store
from guardian_registry.security import check_production_config, decrypt_mobile, encrypt_mobile

from .conftest import AMMA, RAVI


class TestSecretFiles:
    def test_loads_and_strips(self, tmp_path):
        f = tmp_path / "pepper"
        f.write_text("s3cret-pepper\n")
        env = {"GR_PEPPER_FILE": str(f), "OTHER_FILE": "x"}
        assert secrets_store.load_secret_files(env) == ["GR_PEPPER"]
        assert env["GR_PEPPER"] == "s3cret-pepper"

    def test_conflicts_and_bad_files(self, tmp_path):
        f = tmp_path / "k"
        f.write_text("v")
        with pytest.raises(RuntimeError, match="both GR_PEPPER and GR_PEPPER_FILE"):
            secrets_store.load_secret_files({"GR_PEPPER": "a", "GR_PEPPER_FILE": str(f)})
        with pytest.raises(RuntimeError, match="can't read"):
            secrets_store.load_secret_files({"GR_PEPPER_FILE": str(tmp_path / "missing")})
        (tmp_path / "empty").write_text("\n")
        with pytest.raises(RuntimeError, match="empty"):
            secrets_store.load_secret_files({"GR_PEPPER_FILE": str(tmp_path / "empty")})

    def test_production_refuses_the_dev_key_even_in_a_list(self, monkeypatch):
        from guardian_registry.security import _DEV_DATA_KEY
        monkeypatch.setenv("GR_ENV", "production")
        monkeypatch.setenv("GR_PEPPER", "p" * 32)
        monkeypatch.setenv("GR_SMS_PROVIDER", "twilio")
        monkeypatch.setenv("GR_DATA_KEY", Fernet.generate_key().decode() + "," + _DEV_DATA_KEY)
        with pytest.raises(RuntimeError, match="GR_DATA_KEY"):
            check_production_config()


class TestRotation:
    def test_rotate_every_encrypted_column(self, reg, family, monkeypatch):
        old, new = Fernet.generate_key().decode(), Fernet.generate_key().decode()
        monkeypatch.setenv("GR_DATA_KEY", old)
        uid, _ = reg.register_user("+919811111111", "Old Key Person")
        reg.add_push_token(uid, "push-token-old-key", "android")
        reg.db.conn.execute("INSERT INTO pending_changes (id, principal_id, kind, payload, status, requested_by, "
                            "created_at, effective_at) VALUES ('chg_x', ?, 'mobile_change', ?, 'pending', ?, "
                            "'2026-11-23', '2026-11-24')",
                            (uid, json.dumps({"new_mobile_enc": encrypt_mobile("+919822222222"), "x": 1}), uid))
        # the family's rows were written under the development key: include it as an old key too
        from guardian_registry.security import _DEV_DATA_KEY
        monkeypatch.setenv("GR_DATA_KEY", f"{new},{old},{_DEV_DATA_KEY}")
        before = secrets_store.count_unrotated(reg.db)
        assert before >= 3
        out = secrets_store.rotate_data_key(reg.db, limit=2)
        assert sum(out["rotated"].values()) == 2 and out["remaining"] == before - 2
        out = secrets_store.rotate_data_key(reg.db)
        assert out["remaining"] == 0
        assert secrets_store.rotate_data_key(reg.db) == {"rotated": {}, "remaining": 0}  # idempotent

        monkeypatch.setenv("GR_DATA_KEY", new)  # old keys removed: everything still reads
        row = reg.db.one("SELECT mobile_enc FROM users WHERE id=?", (uid,))
        assert decrypt_mobile(row["mobile_enc"]) == "+919811111111"
        for mobile in (AMMA, RAVI):
            assert reg.db.one("SELECT mobile_enc FROM users WHERE id=?", (reg.user_by_mobile(mobile),))
        assert [d["platform"] for d in reg.alert_settings(uid)["push_devices"]] == ["android"]
        payload = json.loads(reg.db.one("SELECT payload FROM pending_changes WHERE id='chg_x'")["payload"])
        assert decrypt_mobile(payload["new_mobile_enc"]) == "+919822222222" and payload["x"] == 1

    def test_admin_endpoint(self, monkeypatch):
        from fastapi.testclient import TestClient

        from guardian_registry.api import create_app
        from guardian_registry.service import Registry

        from .conftest import new_db
        monkeypatch.setenv("GR_ADMIN_TOKEN", "dev-admin-token")
        reg = Registry(new_db())
        reg.register_user(AMMA, "Amma")
        new = Fernet.generate_key().decode()
        from guardian_registry.security import _DEV_DATA_KEY
        monkeypatch.setenv("GR_DATA_KEY", f"{new},{_DEV_DATA_KEY}")
        with TestClient(create_app(reg, run_worker=False)) as c:
            r = c.post("/v1/admin/data-key/rotate", headers={"X-Admin-Token": "dev-admin-token"})
            assert r.status_code == 200 and r.json()["remaining"] == 0
