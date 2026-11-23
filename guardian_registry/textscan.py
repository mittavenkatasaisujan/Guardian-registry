"""Find every person-facing English text the server composes, straight from the source.

Used by tests (and by translators): every alert title and body passed to _alert /
_alert_guardians, and every error message raised in the modules people talk to, turned
into a template where each f-string expression becomes {0}, {1}, ... in order.

    python -m guardian_registry.textscan            # list them
"""

from __future__ import annotations

import ast
from pathlib import Path

PKG = Path(__file__).parent
ALERT_FUNCS = {"_alert": (3, 4), "_alert_guardians": (3, 4)}  # positional index of (title, body) after c
PERSON_MODULES = ("service.py", "recovery.py", "kyc.py", "simswap.py", "devicekeys.py", "channels.py",
                  "privacy.py", "simfeed.py")
PERSON_ERRORS = {"Invalid", "Unauthorized", "Forbidden", "Conflict", "NotFound", "Restricted", "TooMany"}


def template(node: ast.AST) -> str | None:
    """A string literal or f-string -> template with {0}, {1}...; None if it isn't one."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.replace("{", "{{").replace("}", "}}")
    if isinstance(node, ast.JoinedStr):
        out, n = [], 0
        for v in node.values:
            if isinstance(v, ast.Constant):
                out.append(str(v.value).replace("{", "{{").replace("}", "}}"))
            else:
                out.append("{" + str(n) + "}")
                n += 1
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = template(node.left), template(node.right)
        if a is not None and b is not None:  # renumber b's placeholders after a's
            k = a.count("{") - 2 * a.count("{{")
            import re
            b = re.sub(r"\{(\d+)\}", lambda m: "{" + str(int(m.group(1)) + k) + "}", b)
            return a + b
    return None


def templates(node: ast.AST) -> list[str]:
    """Like template(), but `"a" if x else "b"` gives both."""
    if isinstance(node, ast.IfExp):
        return templates(node.body) + templates(node.orelse)
    t = template(node)
    return [t] if t is not None else []


def _calls(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            yield name, node


def alert_templates() -> list[tuple[str, int, str]]:
    """(file, line, template) for every alert title and body."""
    out = []
    for path in sorted(PKG.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for name, node in _calls(tree):
            if name in ALERT_FUNCS and len(node.args) >= 5:
                for i in ALERT_FUNCS[name]:
                    for t in templates(node.args[i]):
                        out.append((path.name, node.lineno, t))
    return out


def error_templates() -> list[tuple[str, int, str]]:
    out = []
    for fname in PERSON_MODULES:
        path = PKG / fname
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                f = node.exc.func
                name = f.id if isinstance(f, ast.Name) else None
                if name in PERSON_ERRORS and node.exc.args:
                    for t in templates(node.exc.args[0]):
                        out.append((fname, node.lineno, t))
    return out


if __name__ == "__main__":
    for kind, items in (("ALERTS", alert_templates()), ("ERRORS", error_templates())):
        uniq = sorted({t for _, _, t in items})
        print(f"# {kind}: {len(uniq)} unique")
        for t in uniq:
            print(repr(t))
