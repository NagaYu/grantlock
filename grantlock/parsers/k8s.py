"""Kubernetes manifest parser.

Two pure stages, because references cross files (a RoleBinding in rbac.yaml
names a ServiceAccount in sa.yaml; a Deployment names a Secret elsewhere):

    load_objects(rel_path, text) -> (objects, warnings)   # one file
    build(objects)               -> (entries, warnings)   # whole repository

Secret ``data`` values are never base64-decoded and ``stringData`` values are
never kept: only key names, the Secret type and a format class are recorded.
"""

from __future__ import annotations

import re
from typing import Any

import yaml

from .. import model
from .common import LineFinder, merge_entries

WORKLOAD_KINDS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob", "ReplicationController"}
RBAC_ROLE_KINDS = {"Role", "ClusterRole"}
RBAC_BINDING_KINDS = {"RoleBinding", "ClusterRoleBinding"}
FEDERATION_ANNOTATIONS = {
    "eks.amazonaws.com/role-arn": "aws",
    "iam.gke.io/gcp-service-account": "gcp",
    "azure.workload.identity/client-id": "azure",
}
SA_TOKEN_TYPE = "kubernetes.io/service-account-token"
DECLARATION_FEDERATION = {
    "aws": "static AWS keys declared although IRSA / EKS Pod Identity is available",
    "gcp": "static GCP key declared although GKE Workload Identity is available",
    "azure": "static Azure secret declared although Azure Workload Identity is available",
}


def looks_like_k8s(text: str) -> bool:
    return bool(re.search(r"^\s*apiVersion:", text, re.M) and re.search(r"^\s*kind:", text, re.M))


def load_objects(rel_path: str, text: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    if not looks_like_k8s(text):
        return [], []
    try:
        nodes = list(yaml.compose_all(text, Loader=yaml.SafeLoader))
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        return [], [{"file": rel_path, "message": f"unparseable Kubernetes YAML near line {mark.line + 1 if mark else '?'} (templated manifest?)"}]
    objs: list[dict[str, Any]] = []
    lines = [n.start_mark.line + 1 if n is not None else 1 for n in nodes]
    for i, doc in enumerate(docs):
        line = lines[i] if i < len(lines) else 1
        items = doc.get("items") if isinstance(doc, dict) and doc.get("kind") == "List" else [doc]
        for d in items or []:
            if isinstance(d, dict) and isinstance(d.get("apiVersion"), str) and isinstance(d.get("kind"), str):
                md = d.get("metadata") if isinstance(d.get("metadata"), dict) else {}
                if not isinstance(md.get("name"), str):
                    continue
                objs.append({"doc": d, "kind": d["kind"], "name": md["name"],
                             "namespace": md.get("namespace") if isinstance(md.get("namespace"), str) else "default",
                             "file": rel_path, "line": line, "text": text})
    return objs, []


def _secret_identity(ns: str, secret: str, key: str | None) -> tuple[str, str, str]:
    """-> (identity_id, provider, credential name) for a Secret key (or a whole Secret)."""
    name = f"{ns}/{secret}" + (f".{key}" if key else "")
    prov = model.infer_provider(key or "", [secret]) if key else model.infer_provider(secret)
    if prov == "unknown" and key:
        prov = model.infer_provider(secret)
    return f"{prov}:k8s-secret:{name}", prov, name


def _sa_identity(ns: str, sa: str) -> str:
    return f"kubernetes:serviceaccount:{ns}/{sa}"


def _pod_spec(kind: str, doc: dict[str, Any]) -> dict[str, Any]:
    spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
    tmpl = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    return tmpl.get("spec") if isinstance(tmpl.get("spec"), dict) else {}


def _rule_scopes(rules: Any, prefix: str) -> list[str]:
    out = []
    for r in rules or []:
        if not isinstance(r, dict):
            continue
        groups = r.get("apiGroups") or [""]
        for verb in r.get("verbs") or []:
            for res in r.get("resources") or []:
                for g in groups:
                    rname = res if g in ("", None) else (f"{res}.{g}" if g != "*" else f"{res}.*")
                    names = r.get("resourceNames") or [None]
                    for n in names:
                        out.append(f"rbac:{prefix}:{verb}:{rname}" + (f"#{n}" if n else ""))
            for url in r.get("nonResourceURLs") or []:
                out.append(f"rbac:{prefix}:{verb}:url:{url}")
    return sorted(set(out))


def build(objects: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    warnings: list[dict[str, str]] = []
    entries: list[dict[str, Any]] = []
    secrets: dict[tuple[str, str], dict[str, Any]] = {}
    sas: dict[tuple[str, str], dict[str, Any]] = {}
    roles: dict[tuple[str, str], dict[str, Any]] = {}
    for o in objects:
        if o["kind"] in ("Secret", "SealedSecret"):
            secrets[(o["namespace"], o["name"])] = o
        elif o["kind"] == "ServiceAccount":
            sas[(o["namespace"], o["name"])] = o
        elif o["kind"] == "Role":
            roles[(o["namespace"], o["name"])] = o
        elif o["kind"] == "ClusterRole":
            roles[("", o["name"])] = o

    def ev(o, needle=None, locator=""):
        lf = LineFinder(o["text"])
        line = (lf.find(needle, o["line"]) if needle else None) or o["line"]
        return [{"file": o["file"], "line": line, "locator": f"{o['kind']}/{o['name']}{('.' + locator) if locator else ''}"}]

    def base_res(o):
        return [{"kind": "namespace", "value": o["namespace"]}]

    def sa_storage(ns, sa):
        o = sas.get((ns, sa))
        ann = ((o or {}).get("doc", {}).get("metadata") or {}).get("annotations") or {}
        for a, prov in FEDERATION_ANNOTATIONS.items():
            if isinstance(ann.get(a), str) and ann[a].strip():
                return "federated", prov, ann[a]
        return "vault_ref", None, None

    # ---- Secrets (declarations) ------------------------------------------
    for (ns, name), o in sorted(secrets.items()):
        comp = model.make_component("k8s_secret", name, o["file"], local_id=f"{o['kind']}/{ns}/{name}")
        d = o["doc"]
        stype = d.get("type") if isinstance(d.get("type"), str) else "Opaque"
        if stype == SA_TOKEN_TYPE:
            sa = ((d.get("metadata") or {}).get("annotations") or {}).get("kubernetes.io/service-account.name", name)
            fed, reason = model.federation_context("k8s_secret", "kubernetes", "vault_ref", "token")
            entries.append(model.make_entry(
                identity=f"kubernetes:sa-token:{ns}/{sa}", component=comp, provider="kubernetes", ctype="token",
                name=f"sa-token:{ns}/{sa}", storage="vault_ref", resources=base_res(o), lifespan="long_lived",
                federation_available=fed, federation_reason=reason, evidence=ev(o, "type:", "type")))
            continue
        blocks = [("data", d.get("data")), ("stringData", d.get("stringData"))]
        if o["kind"] == "SealedSecret":
            blocks = [("encryptedData", (d.get("spec") or {}).get("encryptedData"))]
        for block, values in blocks:
            if not isinstance(values, dict):
                continue
            for key in sorted(values, key=str):
                key = str(key)
                v = values[key]
                ident, prov, cname = _secret_identity(ns, name, key)
                present = isinstance(v, (str, int, float)) and str(v).strip() != ""
                if block == "encryptedData" or not present:
                    storage, fmt = "vault_ref", None
                elif block == "data":
                    storage, fmt = "inline", {"class": "k8s_secret_data_base64", "prefix": None}  # never decoded
                elif model.is_placeholder(str(v)) or model.is_reference(str(v)):
                    storage, fmt = "vault_ref", None
                else:
                    storage, fmt = "inline", model.classify_literal(str(v))
                ctype = model.classify_type(key)
                if ctype == "unknown" and stype == "kubernetes.io/dockerconfigjson":
                    ctype = "token"
                entries.append(model.make_entry(
                    identity=ident, component=comp, provider=prov, ctype=ctype, name=cname, storage=storage, fmt=fmt,
                    resources=base_res(o), evidence=ev(o, f"{key}:", f"{block}.{key}")))

    # ---- ServiceAccounts (declarations) -----------------------------------
    for (ns, name), o in sorted(sas.items()):
        storage, fprov, principal = sa_storage(ns, name)
        res = base_res(o) + ([{"kind": "role", "value": principal}] if principal else [])
        entries.append(model.make_entry(
            identity=_sa_identity(ns, name), component=model.make_component("k8s_service_account", name, o["file"], local_id=f"{ns}/{name}"),
            provider="kubernetes", ctype="service_account", name=f"serviceaccount:{ns}/{name}", storage=storage,
            resources=res, lifespan="ephemeral", evidence=ev(o, "annotations:" if principal else None, "metadata")))

    # ---- RBAC bindings -> scopes on the subject identity ------------------
    bound: set[int] = set()
    for o in sorted((x for x in objects if x["kind"] in RBAC_BINDING_KINDS), key=lambda x: (x["file"], x["line"], x["name"])):
        d = o["doc"]
        ref = d.get("roleRef") if isinstance(d.get("roleRef"), dict) else {}
        rkind, rname = ref.get("kind"), ref.get("name")
        if not isinstance(rname, str):
            continue
        cluster = o["kind"] == "ClusterRoleBinding"
        prefix = "cluster" if cluster else "ns"
        role_obj = roles.get(("", rname)) if rkind == "ClusterRole" else roles.get((o["namespace"], rname))
        if role_obj is not None:
            bound.add(id(role_obj))
            scopes = _rule_scopes(role_obj["doc"].get("rules"), prefix)
            comp_obj = role_obj
        else:
            scopes = [f"role:{rname}"] + ([f"rbac:{prefix}:bound:{rname}"] if cluster else [])
            comp_obj = o
        comp = model.make_component("k8s_rbac", comp_obj["name"], comp_obj["file"], local_id=f"{comp_obj['kind']}/{comp_obj['namespace']}/{comp_obj['name']}")
        for sub in d.get("subjects") or []:
            if not isinstance(sub, dict) or not isinstance(sub.get("name"), str):
                continue
            skind = sub.get("kind")
            if skind == "ServiceAccount":
                sns = sub.get("namespace") or o["namespace"]
                ident, cname = _sa_identity(sns, sub["name"]), f"serviceaccount:{sns}/{sub['name']}"
                storage = sa_storage(sns, sub["name"])[0]
            elif skind in ("User", "Group"):
                ident, cname, storage = f"kubernetes:{skind.lower()}:{sub['name']}", f"{skind.lower()}:{sub['name']}", "federated"
            else:
                continue
            entries.append(model.make_entry(
                identity=ident, component=comp, provider="kubernetes", ctype="service_account", name=cname,
                storage=storage, scopes=scopes, scopes_known=True, scope_source="declared",
                resources=base_res(o), lifespan="ephemeral",
                evidence=ev(comp_obj, "rules:" if comp_obj is role_obj else "roleRef:", "rules" if comp_obj is role_obj else "roleRef")))

    # ---- unbound Role / ClusterRole: the role itself is the identity (D-040) ----
    for (rns, rname), ro in sorted(roles.items()):
        if id(ro) in bound:
            continue  # bound roles are tracked through their subjects (no double counting)
        cluster = ro["kind"] == "ClusterRole"
        ident = f"kubernetes:clusterrole:{rname}" if cluster else f"kubernetes:role:{rns}/{rname}"
        comp = model.make_component("k8s_rbac", rname, ro["file"], local_id=f"{ro['kind']}/{ro['namespace']}/{rname}")
        entries.append(model.make_entry(
            identity=ident, component=comp, provider="kubernetes", ctype="unknown", name=ident.split(":", 1)[1],
            storage="vault_ref", scopes=_rule_scopes(ro["doc"].get("rules"), "cluster" if cluster else "ns"),
            scopes_known=True, scope_source="declared", resources=base_res(ro), lifespan="unknown",
            evidence=ev(ro, "rules:", "rules")))

    # ---- workloads (consumers) --------------------------------------------
    for o in sorted((x for x in objects if x["kind"] in WORKLOAD_KINDS), key=lambda x: (x["file"], x["line"], x["name"])):
        ns = o["namespace"]
        comp = model.make_component("k8s_workload", o["name"], o["file"], local_id=f"{o['kind']}/{ns}/{o['name']}")
        spec = _pod_spec(o["kind"], o["doc"])
        containers = [c for c in (spec.get("containers") or []) + (spec.get("initContainers") or []) if isinstance(c, dict)]
        res = base_res(o) + [{"kind": "image", "value": c["image"]} for c in containers if isinstance(c.get("image"), str)]
        raw: list[dict[str, Any]] = []

        def use_secret(secret: str, key: str | None, locator: str, needle: str, env_name: str | None = None):
            if not isinstance(secret, str):
                return
            keys = [key] if key else None
            if keys is None and (ns, secret) in secrets:
                sd = secrets[(ns, secret)]["doc"]
                found: set[str] = set()
                for block in (sd.get("data"), sd.get("stringData"), (sd.get("spec") or {}).get("encryptedData")):
                    if isinstance(block, dict):
                        found |= {str(k) for k in block}
                keys = sorted(found) or None
            for k in keys or [None]:
                ident, prov, cname = _secret_identity(ns, secret, k)
                ctype = model.classify_type(k or "")
                if ctype == "unknown" and env_name:
                    ctype = model.classify_type(env_name)
                fed, reason = model.federation_context("k8s_workload", prov, "vault_ref", ctype)
                raw.append(model.make_entry(
                    identity=ident, component=comp, provider=prov, ctype=ctype, name=cname, storage="vault_ref",
                    resources=res, federation_available=fed, federation_reason=reason,
                    evidence=ev(o, needle, locator)))

        sa = spec.get("serviceAccountName") or spec.get("serviceAccount")
        if isinstance(sa, str) and sa:
            storage = sa_storage(ns, sa)[0]
            raw.append(model.make_entry(
                identity=_sa_identity(ns, sa), component=comp, provider="kubernetes", ctype="service_account",
                name=f"serviceaccount:{ns}/{sa}", storage=storage, resources=res, lifespan="ephemeral",
                evidence=ev(o, "serviceAccount", "spec.serviceAccountName")))
            if (ns, sa) not in sas:
                warnings.append({"file": o["file"], "message": f"{o['kind']}/{o['name']} uses ServiceAccount '{sa}' not defined in the repository"})
        for ci, c in enumerate(containers):
            for env in c.get("env") or []:
                if not isinstance(env, dict) or not isinstance(env.get("name"), str):
                    continue
                en = env["name"]
                loc = f"containers[{ci}].env.{en}"
                if isinstance(env.get("value"), str):
                    v = env["value"]
                    if model.literal_is_secret(en, v):
                        fmt = model.classify_literal(v)
                        prov = model.infer_provider(en, [o["name"]])
                        if prov == "unknown":
                            prov = model.FORMAT_PROVIDER.get(fmt["class"], "unknown")
                        ctype = model.classify_type(en)
                        if ctype == "unknown":
                            ctype = model.FORMAT_TYPE.get(fmt["class"], "unknown")
                        fed, reason = model.federation_context("k8s_workload", prov, "inline", ctype)
                        raw.append(model.make_entry(
                            identity=model.identity_id(prov, en), component=comp, provider=prov, ctype=ctype, name=en,
                            storage="inline", fmt=fmt, resources=res, federation_available=fed, federation_reason=reason,
                            evidence=ev(o, f"name: {en}", loc)))
                    continue
                vf = env.get("valueFrom") if isinstance(env.get("valueFrom"), dict) else {}
                ref = vf.get("secretKeyRef") if isinstance(vf.get("secretKeyRef"), dict) else None
                if ref:
                    use_secret(ref.get("name"), str(ref.get("key")) if ref.get("key") is not None else None, loc, f"name: {en}", en)
            for ef in c.get("envFrom") or []:
                if isinstance(ef, dict) and isinstance(ef.get("secretRef"), dict):
                    use_secret(ef["secretRef"].get("name"), None, f"containers[{ci}].envFrom", "secretRef")
        for vi, vol in enumerate(spec.get("volumes") or []):
            if isinstance(vol, dict) and isinstance(vol.get("secret"), dict):
                items = vol["secret"].get("items") or []
                keys = [str(i["key"]) for i in items if isinstance(i, dict) and i.get("key") is not None]
                for k in keys or [None]:
                    use_secret(vol["secret"].get("secretName"), k, f"volumes[{vi}]", "secretName")
        for pi, ips in enumerate(spec.get("imagePullSecrets") or []):
            if isinstance(ips, dict) and isinstance(ips.get("name"), str):
                use_secret(ips["name"], None, f"imagePullSecrets[{pi}]", "imagePullSecrets")
        entries += raw

    # ---- declaration-side G6 (D-042): static cloud keys no workload uses ---
    used = {e["identity_id"] for e in entries if e["component"]["kind"] == "k8s_workload"}
    # a Secret any key of which a workload uses is "in use": G6 stays on the workload (no double counting)
    used_secrets = {e["component"]["id"] for e in entries if e["component"]["kind"] == "k8s_secret" and e["identity_id"] in used}
    static_unused = [e for e in entries if e["component"]["kind"] == "k8s_secret"
                     and e["credential"]["provider"] in DECLARATION_FEDERATION
                     and e["credential"]["type"] in model.STATIC_KEY_TYPES and e["component"]["id"] not in used_secrets]
    for e in static_unused:
        e["context"] = {"federation_available": True, "reason": DECLARATION_FEDERATION[e["credential"]["provider"]]}
    for (ns, name), o in sorted(sas.items()):
        if sa_storage(ns, name)[0] == "federated":
            continue
        comp = model.make_component("k8s_service_account", name, o["file"], local_id=f"{ns}/{name}")
        for e in static_unused:
            sec_ns = next((r["value"] for r in e["resources"] if r["kind"] == "namespace"), None)
            if e["component"]["file"] != o["file"] or sec_ns != ns:
                continue  # link only a Secret declared next to the ServiceAccount
            entries.append(model.make_entry(
                identity=e["identity_id"], component=comp, provider=e["credential"]["provider"], ctype=e["credential"]["type"],
                name=e["credential"]["name"], storage="vault_ref", resources=base_res(o), lifespan="long_lived",
                federation_available=True,
                federation_reason=DECLARATION_FEDERATION[e["credential"]["provider"]] + " (ServiceAccount is not federated)",
                evidence=ev(o, None, "metadata")))
    return merge_entries(entries), warnings


def parse_k8s(rel_path: str, text: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Single-file convenience: load + build."""
    objs, w1 = load_objects(rel_path, text)
    entries, w2 = build(objs)
    return entries, w1 + w2
