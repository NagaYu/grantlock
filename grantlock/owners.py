"""CODEOWNERS resolution (deterministic, gitignore-style patterns, last match wins)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

CODEOWNERS_LOCATIONS = [".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"]


@dataclass(frozen=True)
class Rule:
    pattern: str
    owners: tuple[str, ...]
    line: int
    regex: re.Pattern[str]
    source_file: str


def _glob_to_regex(p: str) -> str:
    out = []
    i = 0
    while i < len(p):
        if p.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif p.startswith("/**", i) and i + 3 == len(p):
            out.append("(?:/.*)?")
            i += 3
        elif p.startswith("**", i):
            out.append(".*")
            i += 2
        elif p[i] == "*":
            out.append("[^/]*")
            i += 1
        elif p[i] == "?":
            out.append("[^/]")
            i += 1
        elif p[i] == "\\" and i + 1 < len(p):
            out.append(re.escape(p[i + 1]))
            i += 2
        else:
            out.append(re.escape(p[i]))
            i += 1
    return "".join(out)


def compile_pattern(pattern: str) -> re.Pattern[str]:
    p = pattern
    anchored = p.startswith("/") or "/" in p.rstrip("/")
    p = p.lstrip("/")
    dir_only = p.endswith("/")
    p = p.rstrip("/")
    body = _glob_to_regex(p)
    prefix = "^" if anchored else "^(?:.*/)?"
    last = p.rsplit("/", 1)[-1]
    if dir_only:
        suffix = "/.*$"
    elif "*" in last and "**" not in last:
        # GitHub: `docs/*` matches docs/a.md but not docs/a/b.md
        suffix = "$"
    else:
        suffix = "(?:/.*)?$"
    if p in ("*", "**"):
        return re.compile("^.*$")
    return re.compile(prefix + body + suffix)


def parse_codeowners(text: str, source_file: str = ".github/CODEOWNERS") -> list[Rule]:
    rules: list[Rule] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # strip trailing comment (an unescaped ' #')
        line = re.split(r"\s+#", line, maxsplit=1)[0].strip()
        parts = line.split()
        if not parts:
            continue
        pattern, owners = parts[0], tuple(o for o in parts[1:] if o.startswith("@") or "@" in o)
        if pattern.startswith("\\#"):
            pattern = pattern[1:]
        rules.append(Rule(pattern, owners, lineno, compile_pattern(pattern), source_file))
    return rules


def match(rules: list[Rule], rel_path: str) -> Rule | None:
    hit = None
    for r in rules:
        if r.regex.match(rel_path):
            hit = r
    return hit


def owner_record(rules: list[Rule], rel_path: str) -> dict[str, Any] | None:
    r = match(rules, rel_path)
    if r is None or not r.owners:
        return None
    return {
        "source": "codeowners",
        "owners": list(r.owners),
        "rule": f"{r.source_file}: {r.pattern} {' '.join(r.owners)}",
        "line": r.line,
    }


def declared_record(owners: list[str], component_id: str) -> dict[str, Any]:
    return {"source": "declared", "owners": list(owners), "rule": f"grantlock.policy.json declared_owners[{component_id}]", "line": None}
