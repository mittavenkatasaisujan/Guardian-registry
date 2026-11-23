"""The translation catalog: complete, in sync with the sources, and drafts kept off."""

import importlib.util
import json
from pathlib import Path

import pytest

from guardian_registry import messages

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("i18n_tool", ROOT / "scripts" / "i18n.py")
i18n = importlib.util.module_from_spec(spec)
spec.loader.exec_module(i18n)
DRAFTS = ("ta", "te", "bn", "mr")

from .conftest import AMMA, R  # noqa: E402


def test_catalog_matches_the_sources():
    saved = json.loads((i18n.I18N / "catalog.json").read_text(encoding="utf-8"))
    assert saved == i18n.collect(), "English text changed: run  python scripts/i18n.py collect  and translate"


@pytest.mark.parametrize("code", DRAFTS)
def test_every_language_is_complete_with_its_placeholders(code):
    assert i18n.check(code) == []


def test_drafts_are_off_by_default():
    meta = json.loads((i18n.I18N / "languages.json").read_text(encoding="utf-8"))
    assert all(not meta[c]["enabled"] for c in DRAFTS)
    assert messages.enabled_languages() == ("en", "hi")
    assert messages.normalise("ta-IN") is None and messages.normalise("hi-IN") == "hi"


def test_generated_files_are_current():
    js = (ROOT / "guardian_registry/web/i18n-extra.js").read_text(encoding="utf-8")
    enabled = [c for c, m in i18n.languages().items() if m["enabled"] and c not in ("en", "hi")]
    for c in enabled:
        assert f'"{c}"' in js
    for c in DRAFTS:
        if c not in enabled:
            assert not (ROOT / f"android/app/src/main/res/values-{c}").exists(), f"draft {c} shipped in Android"
            assert not (ROOT / f"ios/GuardianRegistry/{c}.lproj").exists(), f"draft {c} shipped in iOS"


def test_generate_with_drafts(tmp_path):
    written = i18n.generate(include_drafts=True, out_root=tmp_path)
    assert len(written) == 1 + 2 * len(DRAFTS)
    js = (tmp_path / "guardian_registry/web/i18n-extra.js").read_text(encoding="utf-8")
    assert '"Approve": "ஒப்புதல் அளி"' in js and '"ta": "தமிழ்"' in js
    xml = (tmp_path / "android/app/src/main/res/values-te/strings.xml").read_text(encoding="utf-8")
    assert '<string name="approve">ఆమోదించు</string>' in xml
    assert 'name="hello" formatted="true">నమస్కారం, %1$s' in xml
    ios = (tmp_path / "ios/GuardianRegistry/bn.lproj/Localizable.strings").read_text(encoding="utf-8")
    assert '"Approve" = "অনুমোদন করুন";' in ios


class TestEnabledDraft:
    """What happens once a reviewed language is switched on (here with GR_LANGUAGES)."""

    @pytest.fixture(autouse=True)
    def tamil_on(self, monkeypatch):
        monkeypatch.setenv("GR_LANGUAGES", "en,hi,ta")

    def test_alerts_reach_a_tamil_speaker_in_tamil(self, reg, family):
        reg.db.conn.execute("DELETE FROM notifications")
        reg.set_language(family["ravi"], "ta")
        reg.check(family["bank"], AMMA, "t1", 20_000 * R, "known@upi")
        row = reg.db.one("SELECT title, body FROM notifications WHERE recipient_id=? AND kind='approval_needed' "
                         "AND channel='inapp'", (family["ravi"],))
        assert row["title"] == "கட்டணத்திற்கு ஒப்புதல் அளிக்கவா?"
        assert "நிமிடங்களுக்குள் ஒப்புதல் அளியுங்கள்" in row["body"] and "₹20,000" in row["body"]

    def test_errors_and_the_language_list(self, reg):
        from fastapi.testclient import TestClient

        from guardian_registry.api import create_app
        with TestClient(create_app(reg, run_worker=False)) as c:
            langs = c.get("/v1/languages").json()
            assert [x["code"] for x in langs] == ["en", "hi", "ta"]
            r = c.get("/v1/me", headers={"Accept-Language": "ta-IN"})
            assert r.status_code == 401 and "மீண்டும் உள்நுழையுங்கள்" in r.json()["detail"]

    def test_bengali_still_off(self, reg, family):
        from guardian_registry.errors import Invalid
        with pytest.raises(Invalid):
            reg.set_language(family["amma"], "bn")
