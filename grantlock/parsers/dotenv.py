""".env / .env.* declaration parser.

Reads variable *names* only. The text to the right of ``=`` is never bound to
a variable, classified or returned; the only thing inspected there is whether
a quoted value continues onto following lines, so that continuation lines are
not misread as declarations.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any

from .. import model

KIND = "env_decl"
_DECL = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=")
_NON_ENV_SUFFIXES = {"example", "sample", "template", "tmpl", "dist", "defaults", "default", "local", "schema", "tpl"}
# Template files only declare names; any other .env* file is a real environment file that *uses* them (D-044).
TEMPLATE_SUFFIXES = {"example", "sample", "template", "tmpl", "dist", "defaults", "default", "schema", "tpl"}
_PROD = {"production", "prod", "prd", "live"}


def is_env_file(rel_path: str) -> bool:
    base = posixpath.basename(rel_path)
    return base == ".env" or (base.startswith(".env.") and len(base) > 5)


def _environment_of(rel_path: str) -> str | None:
    base = posixpath.basename(rel_path)
    if not base.startswith(".env."):
        return None
    parts = base[5:].lower().split(".")
    for p in parts:
        if p in _NON_ENV_SUFFIXES:
            return None
    return parts[0] or None


def _opens_multiline(rest: str) -> bool:
    """True if the remainder after '=' opens a quote that is not closed on this line."""
    s = rest.lstrip()
    if not s or s[0] not in "\"'":
        return False
    q = s[0]
    i = 1
    while i < len(s):
        if s[i] == "\\" and q == '"':
            i += 2
            continue
        if s[i] == q:
            return False
        i += 1
    return True


def _closes(line: str, q: str) -> bool:
    i = 0
    while i < len(line):
        if line[i] == "\\" and q == '"':
            i += 2
            continue
        if line[i] == q:
            return True
        i += 1
    return False


def declared_names(text: str) -> list[tuple[str, int]]:
    """[(name, line)] in file order. Values are skipped, never captured."""
    out: list[tuple[str, int]] = []
    open_quote: str | None = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        if open_quote is not None:
            if _closes(line, open_quote):
                open_quote = None
            continue
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _DECL.match(line)
        if not m:
            continue
        out.append((m.group(1), lineno))
        if _opens_multiline(line[m.end():]):
            open_quote = line[m.end():].lstrip()[0]
    return out


def is_template(rel_path: str) -> bool:
    base = posixpath.basename(rel_path)
    parts = base[5:].lower().split(".") if base.startswith(".env.") else []
    return any(p in TEMPLATE_SUFFIXES for p in parts)


def parse_env(rel_path: str, text: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    if is_template(rel_path):
        component = model.make_component(KIND, rel_path, rel_path, local_id="decl")
    else:
        component = model.make_component("env_use", rel_path, rel_path, local_id="use")
    env_name = _environment_of(rel_path)
    resources = [{"kind": "environment", "value": env_name}] if env_name else []
    entries: dict[str, dict[str, Any]] = {}
    for name, line in declared_names(text):
        if not model.is_credential_name(name):
            continue
        prov = model.infer_provider(name)
        ctype = model.classify_type(name)
        ident = model.identity_id(prov, name)
        ev = {"file": rel_path, "line": line, "locator": name}
        if ident in entries:
            entries[ident]["evidence"].append(ev)
            continue
        entries[ident] = model.make_entry(
            identity=ident, component=component, provider=prov, ctype=ctype, name=name, storage="env",
            resources=resources, evidence=[ev],
        )
    return [entries[k] for k in sorted(entries)], []
