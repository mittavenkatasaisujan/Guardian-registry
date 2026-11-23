"""How a person wants to be reached: SMS or WhatsApp for urgent alerts, plus push to the
app installs they register. Push tokens are stored encrypted (to send) and hashed (to find)."""

from __future__ import annotations

from .errors import Invalid, NotFound
from .security import encrypt_text, new_id, secret_hash

URGENT_CHANNELS = ("sms", "whatsapp")
PLATFORMS = ("android", "ios", "web")
MAX_PUSH_TOKENS = 5


class ChannelMixin:
    """Mixed into Registry."""

    def alert_settings(self, user_id: str) -> dict:
        u = self._user(user_id)
        tokens = self.db.all("SELECT id, platform, created_at FROM push_tokens WHERE user_id=? ORDER BY created_at",
                             (user_id,))
        return {"urgent_channel": u["urgent_channel"], "push_devices": [dict(t) for t in tokens]}

    def set_urgent_channel(self, user_id: str, channel: str) -> dict:
        if channel not in URGENT_CHANNELS:
            raise Invalid(f"urgent_channel must be one of {list(URGENT_CHANNELS)}")
        with self.db.tx() as c:
            c.execute("UPDATE users SET urgent_channel=? WHERE id=?", (channel, user_id))
            self._audit(c, user_id, "alerts.channel_set", user_id, urgent_channel=channel)
        return self.alert_settings(user_id)

    def add_push_token(self, user_id: str, token: str, platform: str) -> dict:
        token = (token or "").strip()
        if not token or len(token) > 4096:
            raise Invalid("token is required")
        if platform not in PLATFORMS:
            raise Invalid(f"platform must be one of {list(PLATFORMS)}")
        h = secret_hash(token)
        with self.db.tx() as c:
            c.execute("DELETE FROM push_tokens WHERE token_hash=?", (h,))  # a device moves to its new owner
            n = c.execute("SELECT COUNT(*) n FROM push_tokens WHERE user_id=?", (user_id,)).fetchone()["n"]
            if n >= MAX_PUSH_TOKENS:
                oldest = c.execute("SELECT id FROM push_tokens WHERE user_id=? ORDER BY created_at LIMIT 1",
                                   (user_id,)).fetchone()["id"]
                c.execute("DELETE FROM push_tokens WHERE id=?", (oldest,))
            c.execute("INSERT INTO push_tokens VALUES (?,?,?,?,?,?)",
                      (new_id("psh"), user_id, h, encrypt_text(token), platform, self._now()))
            self._audit(c, user_id, "alerts.push_added", user_id, platform=platform)
        return self.alert_settings(user_id)

    def remove_push_token(self, user_id: str, token_id: str) -> dict:
        with self.db.tx() as c:
            if not c.execute("DELETE FROM push_tokens WHERE id=? AND user_id=?", (token_id, user_id)).rowcount:
                raise NotFound("push device not found")
        return self.alert_settings(user_id)

    def _drop_push_tokens(self, c, user_id: str) -> int:
        """A lost phone, or an account recovered onto a new one: stop pushing to old installs."""
        return c.execute("DELETE FROM push_tokens WHERE user_id=?", (user_id,)).rowcount
