"""One translation catalog for everything a person reads, on every platform.

    python scripts/i18n.py collect     # refresh i18n/catalog.json from the sources (English)
    python scripts/i18n.py generate    # write per-platform files for the ENABLED languages
    python scripts/i18n.py missing ta  # list what language "ta" still lacks

Sources of English text (Hindi's tables double as the list of server strings):
  * server: messages.ALERTS_HI / FRAGMENTS_HI / ERRORS_HI / ERROR_FRAGMENTS_HI keys
  * web app: the Hindi table in guardian_registry/web/i18n.js
  * Android: android/app/src/main/res/values/strings.xml
  * iOS: ios/GuardianRegistry/hi.lproj/Localizable.strings keys

Each string gets a stable id (first 10 hex of SHA-1 of the English). A language is
i18n/<code>.json = {"_language": ..., "<id>": "<translation>"}; placeholders ({0}, %1$s, %@)
must survive. i18n/languages.json says which languages are enabled; drafts stay in the repo
but reach no user until a native speaker has reviewed them and the flag is flipped.

`generate` writes (only for enabled languages other than en and hi, which are maintained
directly): guardian_registry/web/i18n-extra.js, android res/values-<code>/strings.xml,
ios <code>.lproj/Localizable.strings. The server reads i18n/<code>.json at run time.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
I18N = ROOT / "guardian_registry" / "i18n"
sys.path.insert(0, str(ROOT))


def sid(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()[:10]


def web_strings() -> list[str]:
    js = (ROOT / "guardian_registry" / "web" / "i18n.js").read_text(encoding="utf-8")
    table = js.split("hi: {", 1)[1].split("\n  },\n};", 1)[0]
    return re.findall(r'"((?:[^"\\]|\\.)*)":', table)


def android_strings() -> dict[str, str]:
    tree = ET.parse(ROOT / "android/app/src/main/res/values/strings.xml")  # nosec B314: our own file
    out = {}
    for s in tree.getroot().iter("string"):
        out[s.get("name")] = (s.text or "").replace("\\'", "'")
    return out


def ios_strings() -> list[str]:
    text = (ROOT / "ios/GuardianRegistry/hi.lproj/Localizable.strings").read_text(encoding="utf-8")
    return [k.replace('\\"', '"') for k in re.findall(r'^"((?:[^"\\]|\\.)*)" = ', text, re.M)]


def collect() -> dict:
    from guardian_registry import messages
    entries: dict[str, dict] = {}

    def add(text, where):
        e = entries.setdefault(sid(text), {"en": text, "where": []})
        if where not in e["where"]:
            e["where"].append(where)

    for name, table in (("alert", messages.ALERTS_HI), ("phrase", messages.FRAGMENTS_HI),
                        ("error", messages.ERRORS_HI), ("error-phrase", messages.ERROR_FRAGMENTS_HI)):
        for k in table:
            add(k, f"server:{name}")
    for k in web_strings():
        add(k.replace('\\"', '"'), "web")
    for name, value in android_strings().items():
        if name != "app_name":
            add(value, f"android:{name}")
    for k in ios_strings():
        add(k, "ios")
    return dict(sorted(entries.items(), key=lambda kv: kv[1]["en"].lower()))


def load(code: str) -> dict:
    p = I18N / f"{code}.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


def languages() -> dict:
    return json.loads((I18N / "languages.json").read_text(encoding="utf-8"))


PLACEHOLDER = re.compile(r"\{\d+\}|\{[a-z]+\}|%\d\$s|%@")


def check(code: str, catalog: dict | None = None) -> list[str]:
    catalog = catalog or json.loads((I18N / "catalog.json").read_text(encoding="utf-8"))
    tr = load(code)
    problems = []
    for k, e in catalog.items():
        if k not in tr:
            problems.append(f"missing {k}: {e['en']}")
        elif sorted(PLACEHOLDER.findall(tr[k])) != sorted(PLACEHOLDER.findall(e["en"])):
            problems.append(f"placeholders differ {k}: {e['en']!r} -> {tr[k]!r}")
    for k in tr:
        if not k.startswith("_") and k not in catalog:
            problems.append(f"unknown id {k} (English changed? re-run collect)")
    return problems


def table(code: str, catalog: dict) -> dict[str, str]:
    """English -> translation for one language."""
    tr = load(code)
    return {e["en"]: tr[k] for k, e in catalog.items() if k in tr}


def _xml_escape(v: str) -> str:
    return (v.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "\\'")
            .replace('"', '\\"'))


def generate(include_drafts: bool = False, out_root: Path = ROOT) -> list[str]:
    catalog = json.loads((I18N / "catalog.json").read_text(encoding="utf-8"))
    langs = languages()
    codes = [c for c, meta in langs.items() if c not in ("en", "hi") and (meta["enabled"] or include_drafts)]
    written = []
    # web
    web = {c: {e["en"]: t for e_id, e in catalog.items() if "web" in e["where"]
               for t in [load(c).get(e_id)] if t} for c in codes}
    names = {c: langs[c]["name"] for c in codes}
    js = ("\"use strict\";\n// Generated by scripts/i18n.py generate from i18n/*.json. Do not edit by hand.\n"
          f"const EXTRA_STRINGS = {json.dumps(web, ensure_ascii=False, indent=1, sort_keys=True)};\n"
          f"const EXTRA_LANGS = {json.dumps(names, ensure_ascii=False, sort_keys=True)};\n")
    p = out_root / "guardian_registry/web/i18n-extra.js"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(js, encoding="utf-8", newline="\n")
    written.append(str(p.relative_to(out_root)))
    # android + ios
    android_names = android_strings()
    for c in codes:
        tr = load(c)
        lines = ['<?xml version="1.0" encoding="utf-8"?>', "<!-- Generated by scripts/i18n.py from i18n/"
                 f"{c}.json. Do not edit by hand. -->", "<resources>"]
        for name, value in android_names.items():
            if name == "app_name":
                continue
            t = tr.get(sid(value))
            if t:
                fmt = ' formatted="true"' if "%1$s" in value else ""
                lines.append(f'    <string name="{name}"{fmt}>{_xml_escape(t)}</string>')
        lines.append("</resources>")
        p = out_root / f"android/app/src/main/res/values-{c}/strings.xml"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        written.append(str(p.relative_to(out_root)))
        ios = [f"/* {langs[c]['name']}. Generated by scripts/i18n.py from i18n/{c}.json. Do not edit by hand. */"]
        for k in ios_strings():
            t = tr.get(sid(k))
            if t:
                ios.append(f'"{k.replace(chr(34), chr(92) + chr(34))}" = "{t.replace(chr(34), chr(92) + chr(34))}";')
        p = out_root / f"ios/GuardianRegistry/{c}.lproj/Localizable.strings"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("\n".join(ios) + "\n", encoding="utf-8", newline="\n")
        written.append(str(p.relative_to(out_root)))
    return written


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    cmd = argv[0] if argv else "help"
    if cmd == "collect":
        cat = collect()
        (I18N / "catalog.json").write_text(json.dumps(cat, ensure_ascii=False, indent=1) + "\n",
                                           encoding="utf-8", newline="\n")
        print(f"{len(cat)} strings in i18n/catalog.json")
        return 0
    if cmd == "generate":
        for w in generate(include_drafts="--drafts" in argv):
            print("wrote", w)
        return 0
    if cmd == "missing" and len(argv) > 1:
        probs = check(argv[1])
        print("\n".join(probs) or "complete")
        return 1 if probs else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
