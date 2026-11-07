"""Shared helpers for surface parsers (pure, no I/O)."""

from __future__ import annotations

import json
import re
from typing import Any, Iterable

STORAGE_RANK = {"inline": 3, "env": 2, "vault_ref": 1, "federated": 0}


class LineFinder:
    """Deterministic best-effort line lookup by searching for key tokens."""

    def __init__(self, text: str):
        self.lines = text.splitlines()

    def find(self, needle: str, start: int = 1, regex: bool = False) -> int | None:
        rx = re.compile(needle) if regex else None
        for i in range(max(start, 1) - 1, len(self.lines)):
            line = self.lines[i]
            if (rx.search(line) if rx else needle in line):
                return i + 1
        return None

    def find_chain(self, needles: Iterable[str], start: int = 1) -> int | None:
        """Find needles in sequence; return the line of the last one found."""
        line = start
        found = None
        for n in needles:
            hit = self.find(n, line)
            if hit is None:
                return found
            found = hit
            line = hit
        return found


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments (outside strings) and trailing commas."""
    out = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        out.append(c)
        i += 1
    cleaned = "".join(out)
    return re.sub(r",(\s*[}\]])", r"\1", cleaned)


def load_jsonc(text: str) -> Any:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return json.loads(strip_jsonc(text))


def merge_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge entries sharing (identity_id, component.id); deterministic."""
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for e in entries:
        key = (e["identity_id"], e["component"]["id"])
        cur = merged.get(key)
        if cur is None:
            merged[key] = e
            continue
        if STORAGE_RANK[e["credential"]["storage"]] > STORAGE_RANK[cur["credential"]["storage"]]:
            cur["credential"]["storage"] = e["credential"]["storage"]
            cur["credential"]["format"] = e["credential"]["format"]
            cur["lifespan"] = e["lifespan"]
        cur["scopes"] = sorted(set(cur["scopes"]) | set(e["scopes"]))
        cur["scopes_known"] = cur["scopes_known"] or e["scopes_known"]
        if cur["scope_source"] == "unknown":
            cur["scope_source"] = e["scope_source"]
        res = {(r["kind"], r["value"]) for r in cur["resources"] + e["resources"]}
        cur["resources"] = [{"kind": k, "value": v} for k, v in sorted(res)]
        if e["context"]["federation_available"] and not cur["context"]["federation_available"]:
            cur["context"] = dict(e["context"])
        ev = {(x["file"], x["line"], x["locator"]) for x in cur["evidence"] + e["evidence"]}
        cur["evidence"] = [
            {"file": f, "line": ln, "locator": loc}
            for f, ln, loc in sorted(ev, key=lambda t: (t[0], t[1] if t[1] is not None else -1, t[2]))
        ]
    return [merged[k] for k in sorted(merged)]
