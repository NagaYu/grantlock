"""findings -> SARIF 2.1.0 (pure)."""

from __future__ import annotations

from typing import Any

from . import __version__
from .diff import TITLES

_LEVEL = {"critical": "error", "warning": "warning", "note": "note"}

RULE_HELP = {
    "G1": "A literal credential value is present in configuration. Move it to a secret store or environment reference and rotate it.",
    "G2": "An existing identity gained scopes/permissions compared to grantlock.json. Review, then run `grantlock lock` to accept.",
    "G3": "A wildcard or admin-level grant (write-all, '*', admin/owner roles). Narrow it to the minimum needed.",
    "G4": "No CODEOWNERS entry or declared owner covers the component that uses this identity.",
    "G5": "The same identity is used by several components; give each component its own credential.",
    "G6": "A long-lived static key is used where federation or short-lived credentials are available.",
    "G7": "An identity is in use that is not declared in grantlock.json. Review, then run `grantlock lock` to accept.",
    "G8": "An identity in grantlock.json is no longer referenced by any component; revoke it and re-lock.",
}


def to_sarif(findings: dict[str, Any]) -> dict[str, Any]:
    rules = [
        {"id": c, "name": TITLES[c].replace(" ", ""), "shortDescription": {"text": TITLES[c]},
         "fullDescription": {"text": RULE_HELP[c]}, "help": {"text": RULE_HELP[c]},
         "defaultConfiguration": {"level": "error" if c in ("G2", "G3", "G7") else "warning"}}
        for c in sorted(TITLES)
    ]
    results = []
    for f in findings["findings"]:
        region = {"startLine": f["line"]} if f["line"] else None
        phys: dict[str, Any] = {"artifactLocation": {"uri": f["file"], "uriBaseId": "%SRCROOT%"}}
        if region:
            phys["region"] = region
        results.append({
            "ruleId": f["class"],
            "ruleIndex": sorted(TITLES).index(f["class"]),
            "level": _LEVEL[f["severity"]],
            "message": {"text": f["message"]},
            "locations": [{"physicalLocation": phys}],
            "partialFingerprints": {"grantlockFindingId/v1": f["finding_id"]},
            "properties": {
                "severity": f["severity"],
                "change": f["change"],
                "identity_id": f["identity_id"],
                "component": f["component"]["id"],
                "production": f["production"]["value"],
                "production_evidence": f["production"]["evidence"],
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "GrantLock", "version": __version__, "informationUri": "https://example.invalid/grantlock",
                                "rules": rules}},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
            "results": results,
            "properties": {"summary": findings["summary"]},
        }],
    }
