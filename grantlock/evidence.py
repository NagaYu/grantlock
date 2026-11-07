"""Evidence pack: an audit artifact built from inventory + lockfile + findings (pure, value-free).

The control mapping is *suggestive*: it points an auditor at the controls a finding
class is relevant to. It is not a certification and makes no compliance claim.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from . import model, schemas
from .diff import TITLES

DISCLAIMER = (
    "Suggestive mapping only. GrantLock findings are indicators relevant to the listed controls; this artifact is not "
    "an attestation, certification or assessment of compliance with NIST SP 800-53 or the SOC 2 Trust Services Criteria. "
    "It contains no secret values or hashes of secret values."
)

NIST = "NIST SP 800-53 Rev. 5"
SOC2 = "SOC 2 TSC 2017"
_C = {
    "IA-5": (NIST, "IA-5", "Authenticator Management"),
    "IA-5(7)": (NIST, "IA-5(7)", "No Embedded Unencrypted Static Authenticators"),
    "AC-6": (NIST, "AC-6", "Least Privilege"),
    "AC-6(5)": (NIST, "AC-6(5)", "Least Privilege | Privileged Accounts"),
    "AC-6(7)": (NIST, "AC-6(7)", "Least Privilege | Review of User Privileges"),
    "CC6.1": (SOC2, "CC6.1", "Logical access security over protected information assets"),
    "CC6.6": (SOC2, "CC6.6", "Logical access security against threats from outside system boundaries"),
}
CONTROL_MAP: dict[str, list[str]] = {
    "G1": ["IA-5", "IA-5(7)", "CC6.1", "CC6.6"],
    "G2": ["AC-6", "CC6.1"],
    "G3": ["AC-6", "AC-6(5)", "CC6.1"],
    "G4": ["IA-5", "AC-6", "CC6.1"],
    "G5": ["IA-5", "AC-6", "CC6.1"],
    "G6": ["IA-5", "CC6.1", "CC6.6"],
    "G7": ["AC-6", "IA-5", "CC6.1"],
    "G8": ["AC-6", "AC-6(7)", "IA-5", "CC6.1"],
}


def _key(e):
    return (e["identity_id"], e["component"]["id"])


def lock_history(previous: dict[str, Any] | None, current: dict[str, Any]) -> dict[str, int] | None:
    if previous is None:
        return None
    pm = {_key(e): e for e in previous["entries"]}
    cm = {_key(e): e for e in current["entries"]}
    pid = {e["identity_id"] for e in previous["entries"]}
    cid = {e["identity_id"] for e in current["entries"]}
    changed = sum(1 for k in pm.keys() & cm.keys()
                  if model.expand_scopes(pm[k]["scopes"]) != model.expand_scopes(cm[k]["scopes"]))
    return {
        "previous_bindings": len(pm), "current_bindings": len(cm),
        "identities_added": len(cid - pid), "identities_removed": len(pid - cid),
        "bindings_added": len(cm.keys() - pm.keys()), "bindings_removed": len(pm.keys() - cm.keys()),
        "bindings_with_scope_changes": changed,
    }


def build_evidence(inventory: dict[str, Any], lockfile: dict[str, Any], findings: dict[str, Any],
                   policy: dict[str, Any], previous_lock: dict[str, Any] | None = None) -> dict[str, Any]:
    for doc, kind in ((inventory, schemas.DOC_INVENTORY), (lockfile, schemas.DOC_LOCK), (findings, schemas.DOC_FINDINGS)):
        schemas.validate(doc, kind)
    entries = inventory["entries"]
    pol = {k: v for k, v in policy.items() if k != "declared_owners"}
    pol["declared_owner_components"] = len(policy.get("declared_owners") or {})
    ev = {
        "schema_version": schemas.SCHEMA_VERSION,
        "document": schemas.DOC_EVIDENCE,
        "generator": dict(model.GENERATOR),
        "disclaimer": DISCLAIMER,
        "inputs": {
            "schema_versions": {"inventory": inventory["schema_version"], "lock": lockfile["schema_version"],
                                "findings": findings["schema_version"], "evidence": schemas.SCHEMA_VERSION},
            "policy": pol,
            "lock_in_sync": findings["summary"]["lock_in_sync"],
        },
        "inventory_summary": {
            "identities": len({e["identity_id"] for e in entries}),
            "bindings": len(entries),
            "by_component_kind": dict(sorted(Counter(e["component"]["kind"] for e in entries).items())),
            "by_storage": dict(sorted(Counter(e["credential"]["storage"] for e in entries).items())),
            "by_lifespan": dict(sorted(Counter(e["lifespan"] for e in entries).items())),
            "owned_bindings": sum(1 for e in entries if e["owner"] is not None),
            "unowned_bindings": sum(1 for e in entries if e["owner"] is None),
        },
        "findings_summary": {
            "by_class": dict(sorted(Counter(f["class"] for f in findings["findings"]).items())),
            "by_severity": dict(sorted(Counter(f["severity"] for f in findings["findings"]).items())),
            "exit_code": findings["summary"]["exit_code"],
        },
        "findings": [{
            "finding_id": f["finding_id"], "class": f["class"], "title": f["title"], "severity": f["severity"],
            "change": f["change"], "identity_id": f["identity_id"], "component_id": f["component"]["id"],
            "file": f["file"], "line": f["line"], "production_evidence": list(f["production"]["evidence"]),
            "rationale": f["message"], "controls": list(CONTROL_MAP[f["class"]]),
        } for f in findings["findings"]],
        "lock_history": lock_history(previous_lock, lockfile),
        "control_mapping": {
            "nature": "suggestive (non-authoritative) mapping from GrantLock finding classes to control identifiers",
            "by_class": {c: [{"framework": _C[x][0], "control": _C[x][1], "title": _C[x][2]} for x in CONTROL_MAP[c]]
                         for c in schemas.CLASSES},
        },
    }
    schemas.validate(ev, schemas.DOC_EVIDENCE)
    return ev


def render_markdown(ev: dict[str, Any]) -> str:
    s = ev["inventory_summary"]
    fs = ev["findings_summary"]
    out = ["# GrantLock evidence pack", "", f"> {ev['disclaimer']}", "",
           f"- generator: {ev['generator']['name']} {ev['generator']['version']}",
           "- schema versions: " + ", ".join(f"{k} {v}" for k, v in ev["inputs"]["schema_versions"].items()),
           f"- lockfile in sync with repository: {'yes' if ev['inputs']['lock_in_sync'] else 'no'}",
           f"- CI gate result (exit code): {fs['exit_code']}", "",
           "## Inventory", "", f"{s['identities']} identities in {s['bindings']} bindings "
           f"({s['owned_bindings']} owned, {s['unowned_bindings']} without owner).", "",
           "| dimension | counts |", "|---|---|",
           "| component kind | " + ", ".join(f"{k}: {v}" for k, v in s["by_component_kind"].items()) + " |",
           "| storage | " + ", ".join(f"{k}: {v}" for k, v in s["by_storage"].items()) + " |",
           "| lifespan | " + ", ".join(f"{k}: {v}" for k, v in s["by_lifespan"].items()) + " |", "",
           "## Findings", "",
           "by class: " + (", ".join(f"{k} {v}" for k, v in fs["by_class"].items()) or "none") +
           "; by severity: " + (", ".join(f"{k} {v}" for k, v in fs["by_severity"].items()) or "none"), ""]
    if ev["findings"]:
        out += ["| class | severity | change | location | identity | controls |", "|---|---|---|---|---|---|"]
        for f in ev["findings"]:
            loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
            out.append(f"| {f['class']} | {f['severity']} | {f['change']} | `{loc}` | `{f['identity_id']}` | {', '.join(f['controls'])} |")
        out.append("")
    lh = ev["lock_history"]
    out += ["## Lockfile history", ""]
    out.append("No previous lockfile supplied." if lh is None else
               f"{lh['previous_bindings']} → {lh['current_bindings']} bindings; identities +{lh['identities_added']} / "
               f"-{lh['identities_removed']}; bindings +{lh['bindings_added']} / -{lh['bindings_removed']}; "
               f"{lh['bindings_with_scope_changes']} binding(s) with scope changes.")
    out += ["", "## Control mapping (suggestive)", "", "| class | controls |", "|---|---|"]
    for c, ctrls in ev["control_mapping"]["by_class"].items():
        out.append(f"| {c} {TITLES[c]} | " + "; ".join(f"{x['control']} {x['title']}" for x in ctrls) + " |")
    return "\n".join(out) + "\n"
