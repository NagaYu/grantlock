"""diff(inventory, lockfile, policy) -> findings. Pure; never writes anything."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from . import model, policy as policy_mod, schemas

TITLES = {
    "G1": "Inline secret value in configuration",
    "G2": "Scope / permission added to an existing identity",
    "G3": "Wildcard or admin-level grant",
    "G4": "Identity without an owner",
    "G5": "Identity shared by multiple components",
    "G6": "Long-lived static key where federation / short-lived credentials are available",
    "G7": "New identity not declared in grantlock.json",
    "G8": "Dormant grant: locked identity no longer referenced",
}


def _key(e: dict[str, Any]) -> tuple[str, str]:
    return (e["identity_id"], e["component"]["id"])


def _consuming(e: dict[str, Any]) -> bool:
    return e["component"]["kind"] not in schemas.DECLARATION_KINDS


def _sharing(e: dict[str, Any]) -> bool:
    return e["component"]["kind"] not in schemas.SHARING_EXCLUDED_KINDS


def _first_line(e: dict[str, Any]) -> int | None:
    ev = e.get("evidence") or []
    return ev[0]["line"] if ev else None


def _g6(e: dict[str, Any]) -> bool:
    return bool(e["context"]["federation_available"]) and e["lifespan"] == "long_lived" and e["credential"]["storage"] != "federated"


def diff(inventory: dict[str, Any], lockfile: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, Any]:
    schemas.validate(inventory, schemas.DOC_INVENTORY)
    schemas.validate(lockfile, schemas.DOC_LOCK)
    pol = policy if policy is not None else policy_mod.default_policy()

    inv = sorted(inventory["entries"], key=_key)
    lck = sorted(lockfile["entries"], key=_key)
    lock_map = {_key(e): e for e in lck}
    inv_map = {_key(e): e for e in inv}
    lock_ids = {e["identity_id"] for e in lck}
    lock_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for le in lck:
        lock_by_id[le["identity_id"]].append(le)

    inv_consumers: dict[str, set[str]] = defaultdict(set)
    lock_consumers: dict[str, set[str]] = defaultdict(set)
    inv_sharers: dict[str, set[str]] = defaultdict(set)
    lock_sharers: dict[str, set[str]] = defaultdict(set)
    inv_ids = set()
    for e in inv:
        inv_ids.add(e["identity_id"])
        if _consuming(e):
            inv_consumers[e["identity_id"]].add(e["component"]["id"])
        if _sharing(e):
            inv_sharers[e["identity_id"]].add(e["component"]["id"])
    for e in lck:
        if _consuming(e):
            lock_consumers[e["identity_id"]].add(e["component"]["id"])
        if _sharing(e):
            lock_sharers[e["identity_id"]].add(e["component"]["id"])

    findings: list[dict[str, Any]] = []
    drift: list[dict[str, Any]] = []

    def emit(cls: str, e: dict[str, Any], change: str, details: dict[str, Any], message: str, line: int | None) -> None:
        is_prod, prod_ev = policy_mod.production(e, pol)
        sev = policy_mod.severity_for(cls, is_prod, change, pol)
        if sev is None:
            return
        findings.append({
            "finding_id": f"{cls}:{e['identity_id']}:{e['component']['id']}",
            "class": cls,
            "title": TITLES[cls],
            "severity": sev,
            "change": change,
            "identity_id": e["identity_id"],
            "component": dict(e["component"]),
            "file": e["component"]["file"],
            "line": line,
            "production": {"value": is_prod, "evidence": prod_ev},
            "details": details,
            "message": message,
        })

    for e in inv:
        prev = lock_map.get(_key(e))
        cred = e["credential"]
        cname = f"{e['component']['kind']} '{e['component']['name']}'"
        line = _first_line(e)

        # G1 inline secret value
        if cred["storage"] == "inline":
            change = "unchanged" if prev and prev["credential"]["storage"] == "inline" else "introduced"
            emit("G1", e, change, {"format": cred["format"], "previous_storage": prev["credential"]["storage"] if prev else None},
                 f"{cname} embeds a literal {cred['format']['class']} credential ({cred['name']}); the value was not recorded.",
                 line)

        # G2 scope added to an existing identity binding
        if prev is not None:
            added = sorted(model.expand_scopes(e["scopes"]) - model.expand_scopes(prev["scopes"])) if prev["scopes_known"] and e["scopes_known"] else []
            # write implies read: when both are new, report only the write
            added = [s for s in added if not (s.endswith(":read") and s[:-5] + ":write" in added)]
            src_change = []
            if prev["scopes_known"] and not e["scopes_known"]:
                src_change = [prev["scope_source"], e["scope_source"]]
            if added or src_change:
                d: dict[str, Any] = {"added_scopes": added}
                if src_change:
                    d["scope_source_change"] = src_change
                msg = (f"{cname}: {e['identity_id']} gained " + (", ".join(added) if added else "") +
                       (f"{'; ' if added else ''}permissions changed from {src_change[0]} to {src_change[1]} (no longer bounded)" if src_change else ""))
                emit("G2", e, "introduced", d, msg, line)
            removed = model.expand_scopes(prev["scopes"]) - model.expand_scopes(e["scopes"])
            if removed and e["scopes_known"]:
                drift.append({"kind": "scopes_removed", "identity_id": e["identity_id"], "component_id": e["component"]["id"]})
            if not prev["scopes_known"] and e["scopes_known"]:
                drift.append({"kind": "scopes_became_known", "identity_id": e["identity_id"], "component_id": e["component"]["id"]})
            for field, kind in (("owner", "owner_changed"), ("resources", "resources_changed"), ("lifespan", "lifespan_changed")):
                if prev[field] != e[field]:
                    drift.append({"kind": kind, "identity_id": e["identity_id"], "component_id": e["component"]["id"]})
            if prev["credential"]["storage"] != cred["storage"]:
                drift.append({"kind": "storage_changed", "identity_id": e["identity_id"], "component_id": e["component"]["id"]})
        elif e["identity_id"] in lock_ids:
            drift.append({"kind": "binding_added", "identity_id": e["identity_id"], "component_id": e["component"]["id"]})
            # A new *grant* component (RBAC binding, IAM member/attachment/policy) for an existing identity adds
            # permissions to that identity even though the (identity, component) pair is new (D-031).
            if e["component"]["kind"] in schemas.DECLARATION_KINDS and e["scopes_known"] and e["scopes"]:
                held = model.expand_scopes(s for le in lock_by_id.get(e["identity_id"], []) for s in le["scopes"])
                added = sorted(model.expand_scopes(e["scopes"]) - held)
                added = [s for s in added if not (s.endswith(":read") and s[:-5] + ":write" in added)]
                if added:
                    emit("G2", e, "introduced", {"added_scopes": added},
                         f"{cname}: new grant for existing identity {e['identity_id']} adds " + ", ".join(added), line)

        # G3 wildcard / admin-level
        reasons = model.wildcard_reasons(e["scopes"], e["scope_source"])
        if reasons:
            prev_reasons = set(model.wildcard_reasons(prev["scopes"], prev["scope_source"])) if prev else set()
            change = "unchanged" if prev and set(reasons) <= prev_reasons else "introduced"
            emit("G3", e, change, {"wildcard_reasons": reasons}, f"{cname}: {e['identity_id']} holds " + "; ".join(reasons), line)

        # G4 no owner
        if e["owner"] is None:
            change = "unchanged" if prev and prev["owner"] is None else "introduced"
            emit("G4", e, change, {}, f"{cname} ({e['component']['file']}) has no CODEOWNERS entry or declared owner for {e['identity_id']}", line)

        # G5 shared identity
        if _sharing(e) and len(inv_sharers[e["identity_id"]]) > 1:
            others = sorted(inv_sharers[e["identity_id"]] - {e["component"]["id"]})
            locked = lock_sharers.get(e["identity_id"], set())
            change = "unchanged" if len(locked) > 1 and inv_sharers[e["identity_id"]] <= locked else "introduced"
            emit("G5", e, change, {"shared_with": others},
                 f"{e['identity_id']} is used by {len(inv_sharers[e['identity_id']])} components", line)

        # G6 long-lived static key where federation is available
        if _g6(e):
            change = "unchanged" if prev and _g6(prev) else "introduced"
            emit("G6", e, change, {"federation_reason": e["context"]["reason"]},
                 f"{cname} uses long-lived {cred['provider']} credential {cred['name']}; {e['context']['reason']}", line)

        # G7 new identity
        if e["identity_id"] not in lock_ids:
            emit("G7", e, "introduced", {}, f"{cname} uses {e['identity_id']}, which is not in grantlock.json", line)

    # G8 dormant grants + removed bindings
    inv_components = {e["component"]["id"] for e in inv}
    for le in lck:
        ident = le["identity_id"]
        now_consumers = inv_consumers.get(ident, set())
        was_consumers = lock_consumers.get(ident, set())
        dormant = not now_consumers and (bool(was_consumers) or ident not in inv_ids)
        if dormant and ident.startswith(("kubernetes:role:", "kubernetes:clusterrole:")) and le["component"]["id"] in inv_components:
            dormant = False  # an unbound role that became bound is still defined (D-040)
        if dormant and (_consuming(le) or not was_consumers):
            emit("G8", le, "removed", {},
                 f"{ident} is locked for {le['component']['kind']} '{le['component']['name']}' but no component references it any more", None)
        elif _key(le) not in inv_map:
            drift.append({"kind": "binding_removed", "identity_id": ident, "component_id": le["component"]["id"]})

    findings.sort(key=lambda f: (schemas.CLASSES.index(f["class"]), f["file"], f["identity_id"], f["component"]["id"]))
    drift.sort(key=lambda d: (d["kind"], d["identity_id"], d["component_id"]))
    by_class = {c: sum(1 for f in findings if f["class"] == c) for c in schemas.CLASSES}
    crit = sum(1 for f in findings if f["severity"] == "critical")
    from .lockfile import lock as _lock  # local import: lockfile imports nothing from diff
    in_sync = _lock(inventory)["entries"] == lockfile["entries"]
    doc = {
        "schema_version": schemas.SCHEMA_VERSION,
        "document": schemas.DOC_FINDINGS,
        "generator": dict(model.GENERATOR),
        "summary": {
            "critical": crit,
            "warning": sum(1 for f in findings if f["severity"] == "warning"),
            "note": sum(1 for f in findings if f["severity"] == "note"),
            "total": len(findings),
            "by_class": by_class,
            "exit_code": 1 if crit else 0,
            "lock_in_sync": in_sync,
        },
        "findings": findings,
        "drift": drift,
    }
    schemas.validate(doc, schemas.DOC_FINDINGS)
    return doc
