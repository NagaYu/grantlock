"""Severity policy (grantlock.policy.json) and the production heuristic."""

from __future__ import annotations

import copy
import json
import os
import re
from typing import Any

from . import schemas

POLICY_FILENAME = "grantlock.policy.json"

DEFAULT_PRODUCTION_PATTERNS = [r"(^|[^a-z0-9])(prod|production|prd|live)([^a-z0-9]|$)"]

_DEFAULT_SEVERITY = {
    c: {"production": "critical" if c in ("G2", "G3", "G7") else "warning", "non_production": "warning"}
    for c in schemas.CLASSES
}


class PolicyError(ValueError):
    pass


def default_policy() -> dict[str, Any]:
    return {
        "schema_version": schemas.SCHEMA_VERSION,
        "document": schemas.DOC_POLICY,
        "severity": copy.deepcopy(_DEFAULT_SEVERITY),
        "production_patterns": list(DEFAULT_PRODUCTION_PATTERNS),
        "declared_owners": {},
        "strict_recorded_g3": False,
    }


def merge_policy(user: dict[str, Any] | None) -> dict[str, Any]:
    pol = default_policy()
    if not user:
        return pol
    errs = schemas.validation_errors(user, schemas.DOC_POLICY)
    if errs:
        raise PolicyError("grantlock.policy.json schema violation: " + "; ".join(errs[:5]))
    for cls, pair in (user.get("severity") or {}).items():
        pol["severity"][cls] = dict(pair)
    if "production_patterns" in user:
        pol["production_patterns"] = list(user["production_patterns"])
    for p in pol["production_patterns"]:
        try:
            re.compile(p)
        except re.error as exc:
            raise PolicyError(f"invalid production pattern {p!r}: {exc}") from None
    pol["declared_owners"] = dict(user.get("declared_owners") or {})
    pol["strict_recorded_g3"] = bool(user.get("strict_recorded_g3", False))
    return pol


def load_policy(path: str | os.PathLike[str] | None) -> dict[str, Any]:
    if path is None or not os.path.isfile(path):
        return default_policy()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            user = json.load(fh)
    except (OSError, ValueError) as exc:
        raise PolicyError(f"cannot read policy: {exc.__class__.__name__}") from None
    return merge_policy(user)


# every resource kind except triggers (event names are not deployment targets)
_PROD_RESOURCE_KINDS = ("environment", "host", "role", "branch", "image", "package", "namespace", "cloud_resource")


def production(entry: dict[str, Any], pol: dict[str, Any]) -> tuple[bool, list[str]]:
    """Deterministic production heuristic. Returns (is_production, evidence)."""
    rxs = [re.compile(p, re.IGNORECASE) for p in pol["production_patterns"]]
    ev: list[str] = []

    def check(label: str, value: str) -> None:
        for rx in rxs:
            if rx.search(value):
                ev.append(f"{label} '{value}' matches production pattern")
                return

    for r in entry.get("resources", []):
        if r["kind"] in _PROD_RESOURCE_KINDS:
            check(f"{r['kind']}", r["value"])
    check("component", entry["component"]["name"])
    cname = entry["credential"]["name"]
    if not cname.startswith(("mcp_server:", "gha_workflow:")):
        check("credential name", cname)
    return bool(ev), ev


def severity_for(cls: str, is_prod: bool, change: str, pol: dict[str, Any]) -> str | None:
    sev = pol["severity"][cls]["production" if is_prod else "non_production"]
    if sev == "off":
        return None
    if change == "unchanged" and sev == "critical":
        # already recorded in the committed lockfile = reviewed via `grantlock lock` (D-010),
        # unless the policy opts into strict handling of recorded G3 grants.
        if cls == "G3" and pol.get("strict_recorded_g3", False):
            return sev
        return "warning"
    return sev
