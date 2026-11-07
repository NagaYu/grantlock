"""GitHub Actions workflow parser.

Pure: ``parse_workflow(rel_path, text) -> (entries, warnings)``. Reads
``permissions:`` (workflow and job level), ``secrets.*`` references, OIDC
(``id-token: write`` + cloud auth actions) and static cloud key usage.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any, Iterator

import yaml

from .. import model
from .common import LineFinder, merge_entries

KIND = "gha_workflow"
_MISSING = object()

_EXPR = re.compile(r"\$\{\{(.*?)\}\}", re.DOTALL)
# `secrets` must be the context name itself, not the tail of e.g. `steps.redact_secrets.outcome` (D-036)
_SECRET_REF = re.compile(r"(?<![\w.-])secrets\.([A-Za-z_][A-Za-z0-9_-]*)|(?<![\w.-])secrets\[\s*['\"]([^'\"]+)['\"]\s*\]")
_VARS_REF = re.compile(r"vars\.([A-Za-z_][A-Za-z0-9_-]*)")

# Cloud / registry auth actions. static_inputs carry long-lived material;
# identifier_inputs only name a federated principal and are not credentials.
AUTH_ACTIONS: dict[str, dict[str, Any]] = {
    "aws-actions/configure-aws-credentials": {
        "provider": "aws",
        "static_inputs": {"aws-access-key-id": "api_key", "aws-secret-access-key": "api_key",
                          "aws-session-token": "token"},
        "subject_inputs": ["role-to-assume"],
        "identifier_inputs": {"role-to-assume", "aws-region", "role-session-name", "audience",
                              "role-external-id"},
    },
    "google-github-actions/auth": {
        "provider": "gcp",
        "static_inputs": {"credentials_json": "service_account"},
        "subject_inputs": ["service_account", "workload_identity_provider"],
        "identifier_inputs": {"workload_identity_provider", "service_account", "project_id", "audience"},
    },
    "azure/login": {
        "provider": "azure",
        "static_inputs": {"creds": "service_account", "client-secret": "oauth"},
        "subject_inputs": ["client-id"],
        "identifier_inputs": {"client-id", "tenant-id", "subscription-id", "environment", "audience"},
    },
    "pypa/gh-action-pypi-publish": {
        "provider": "pypi",
        "static_inputs": {"password": "token"},
        "subject_inputs": [],
        "identifier_inputs": {"repository-url", "user", "packages-dir"},
    },
}


def normalize_permissions(perms: Any) -> tuple[list[str], str, bool]:
    """-> (scopes, scope_source, scopes_known)."""
    if perms is _MISSING or perms is None:
        return [], "implicit_default", False
    if perms == "read-all":
        return [f"{s}:read" for s in model.GHA_SCOPES], "read-all", True
    if perms == "write-all":
        return [f"{s}:write" for s in model.GHA_SCOPES], "write-all", True
    if isinstance(perms, dict):
        out = []
        for k in sorted(perms):
            lvl = str(perms[k]).strip().lower()
            if lvl not in model.GHA_LEVELS:
                continue
            if lvl != "none":
                out.append(f"{str(k).strip().lower()}:{lvl}")
        return out, "explicit", True
    return [], "implicit_default", False


def _action_name(uses: str) -> str:
    return uses.split("@", 1)[0].strip().lower()


def _secret_refs(value: str, key: str | None) -> list[str]:
    exprs = [m.group(1) for m in _EXPR.finditer(value)]
    if key == "if":
        exprs.append(value)
    names: list[str] = []
    for ex in exprs:
        for m in _SECRET_REF.finditer(ex):
            n = m.group(1) or m.group(2)
            if n not in names:
                names.append(n)
    return names


def _subject(value: str) -> str:
    refs = _secret_refs(value, None)
    if refs:
        return f"secrets.{refs[0]}"
    exprs = [m.group(1) for m in _EXPR.finditer(value)]
    for ex in exprs:
        m = _VARS_REF.search(ex)
        if m:
            return f"vars.{m.group(1)}"
    if exprs:
        return "expr"
    return value.strip()


def _role_scope(provider: str, subject: str) -> list[str]:
    if subject.startswith(("secrets.", "vars.")) or subject == "expr" or not subject:
        return []
    if provider == "aws":
        return [f"role:{subject.rsplit('/', 1)[-1]}"]
    if provider == "gcp":
        return [f"service_account:{subject.split('@', 1)[0]}"] if "@" in subject else []
    return []


def _triggers(on: Any) -> list[dict[str, str]]:
    res: list[dict[str, str]] = []
    if isinstance(on, str):
        res.append({"kind": "trigger", "value": on})
    elif isinstance(on, list):
        res += [{"kind": "trigger", "value": str(x)} for x in on]
    elif isinstance(on, dict):
        for ev in on:
            res.append({"kind": "trigger", "value": str(ev)})
            spec = on[ev]
            if isinstance(spec, dict):
                for b in spec.get("branches", []) or []:
                    res.append({"kind": "branch", "value": str(b)})
    return res


def _environment(job: dict[str, Any]) -> str | None:
    env = job.get("environment")
    if isinstance(env, str):
        return env
    if isinstance(env, dict) and isinstance(env.get("name"), str):
        return env["name"]
    return None


def _walk(obj: Any, path: list[str], parent_key: str | None = None) -> Iterator[tuple[list[str], str | None, str | None, str]]:
    """Yield (path, parent_key, key, string_value) for every string leaf."""
    if isinstance(obj, dict):
        for k in obj:
            v = obj[k]
            ks = str(k)
            if isinstance(v, str):
                yield path + [ks], parent_key, ks, v
            else:
                yield from _walk(v, path + [ks], ks)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                yield path + [f"[{i}]"], parent_key, None, v
            else:
                yield from _walk(v, path + [f"[{i}]"], parent_key)


_RUN_TOKEN_SPLIT = re.compile(r"[\s'\"=,;()<>|&]+")


def parse_workflow(rel_path: str, text: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    warnings: list[dict[str, str]] = []
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        return [], [{"file": rel_path, "message": f"invalid YAML near line {mark.line + 1 if mark else '?'}"}]
    if not isinstance(doc, dict):
        return [], [{"file": rel_path, "message": "workflow is not a mapping"}]
    if True in doc and "on" not in doc:  # YAML 1.1: `on:` parses as boolean True
        doc["on"] = doc.pop(True)
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return [], [{"file": rel_path, "message": "workflow has no jobs mapping"}]

    stem = posixpath.splitext(posixpath.basename(rel_path))[0]
    wf_name = doc["name"] if isinstance(doc.get("name"), str) and doc["name"].strip() else stem
    wf_perms = doc.get("permissions", _MISSING)
    wf_env = doc.get("env") if isinstance(doc.get("env"), dict) else {}
    triggers = _triggers(doc.get("on"))
    lf = LineFinder(text)
    jobs_line = lf.find(r"^jobs:\s*(#.*)?$", regex=True) or 1

    entries: list[dict[str, Any]] = []
    for job_id in sorted(jobs, key=str):
        job = jobs[job_id]
        if not isinstance(job, dict):
            continue
        job_id = str(job_id)
        job_line = lf.find(rf"^\s+['\"]?{re.escape(job_id)}['\"]?:\s*(#.*)?$", jobs_line, regex=True) or jobs_line
        entries += _parse_job(rel_path, wf_name, wf_perms, wf_env, triggers, job_id, job, lf, job_line, warnings)
    return merge_entries(entries), warnings


def _parse_job(rel_path, wf_name, wf_perms, wf_env, triggers, job_id, job, lf, job_line, warnings):
    component = model.make_component(KIND, f"{wf_name}/{job_id}", rel_path, local_id=job_id)
    perms_raw = job.get("permissions", _MISSING)
    if perms_raw is _MISSING:
        perms_raw = wf_perms
    scopes, scope_source, scopes_known = normalize_permissions(perms_raw)
    if perms_raw is not _MISSING and perms_raw is not None and scope_source == "implicit_default":
        warnings.append({"file": rel_path, "message": f"job '{job_id}': unrecognized permissions value"})
    has_id_token = "id-token:write" in scopes
    resources = list(triggers)
    env_name = _environment(job)
    if env_name:
        resources.append({"kind": "environment", "value": env_name})
    if isinstance(job.get("uses"), str) and job.get("secrets") == "inherit":
        warnings.append({"file": rel_path, "message": f"job '{job_id}': 'secrets: inherit' passes all repository secrets to a reusable workflow (not enumerated in Phase 1)"})

    out: list[dict[str, Any]] = []
    base = f"jobs.{job_id}"

    def line_of(*needles: str) -> int:
        return lf.find_chain(needles, job_line) or job_line

    # 1) the job's implicit GITHUB_TOKEN (minted per job)
    perm_line = lf.find(r"^\s+permissions:", job_line, regex=True)
    out.append(model.make_entry(
        identity=f"github:GITHUB_TOKEN@{rel_path}#{job_id}", component=component, provider="github",
        ctype="token", name="GITHUB_TOKEN", storage="vault_ref", scopes=scopes, scopes_known=scopes_known,
        scope_source=scope_source, resources=resources, lifespan="ephemeral",
        evidence=[{"file": rel_path, "line": job_line, "locator": f"{base}.permissions" if "permissions" in job else (
            "permissions" if wf_perms is not _MISSING else f"{base} (implicit default permissions)")}],
    ))
    del perm_line

    absorbed: set[tuple[str, ...]] = set()  # paths of identifier inputs of federated auth steps
    static_override: dict[tuple[str, ...], tuple[str, str]] = {}  # path -> (provider, type)

    # 2) cloud auth actions: federated or static
    steps = job.get("steps") if isinstance(job.get("steps"), list) else []
    for i, step in enumerate(steps):
        if not isinstance(step, dict) or not isinstance(step.get("uses"), str):
            continue
        action = _action_name(step["uses"])
        spec = AUTH_ACTIONS.get(action)
        if spec is None:
            continue
        with_ = step.get("with") if isinstance(step.get("with"), dict) else {}
        spath = ["steps", f"[{i}]", "with"]
        static_keys = [k for k in spec["static_inputs"] if isinstance(with_.get(k), str) and with_[k].strip()]
        if static_keys:
            for k in static_keys:
                static_override[tuple(spath + [k])] = (spec["provider"], spec["static_inputs"][k])
            continue
        subject = None
        for sk in spec["subject_inputs"]:
            if isinstance(with_.get(sk), str) and with_[sk].strip():
                subject = _subject(with_[sk])
                break
        if spec["provider"] == "pypi":
            subject = "trusted-publisher"
        if subject is None:
            continue
        for k in spec["identifier_inputs"]:
            absorbed.add(tuple(spath + [k]))
        if not has_id_token:
            warnings.append({"file": rel_path, "message": f"job '{job_id}': {action} configured for OIDC but 'id-token: write' is not granted"})
        role_scopes = _role_scope(spec["provider"], subject)
        res = list(resources)
        if role_scopes:
            res.append({"kind": "role", "value": role_scopes[0].split(":", 1)[1]})
        out.append(model.make_entry(
            identity=f"{spec['provider']}:oidc:{subject}", component=component, provider=spec["provider"],
            ctype="service_account", name=f"oidc:{subject}", storage="federated",
            scopes=role_scopes, scopes_known=bool(role_scopes), scope_source="declared" if role_scopes else "unknown",
            resources=res, lifespan="ephemeral",
            evidence=[{"file": rel_path, "line": line_of(step["uses"].split("@")[0]), "locator": f"{base}.steps[{i}].uses"}],
        ))

    # 3) secrets references and inline literals across workflow env + job body
    # workflow-level env is not propagated to reusable-workflow call jobs (`jobs.<id>.uses`)
    sources = [] if isinstance(job.get("uses"), str) else [(["env"], wf_env, "workflow", "env")]
    sources.append(([], job, "job", None))
    for prefix, obj, origin, top_parent in sources:
        for path, parent_key, key, value in _walk(obj, prefix, top_parent):
            tpath = tuple(path)
            loc = ("" if origin == "workflow" else base + ".") + ".".join(path)
            loc = loc.replace(".[", "[")
            refs = _secret_refs(value, key)
            for name in refs:
                if name == "GITHUB_TOKEN":
                    continue
                if tpath in absorbed:
                    continue
                prov, ctype = static_override.get(tpath, (None, None))
                ctx = [str(step.get("uses", "")) for step in steps if isinstance(step, dict)]
                prov = prov or model.infer_provider(name, ctx if parent_key == "with" else [])
                ctype = ctype or model.classify_type(name)
                fed, reason = model.federation_context(KIND, prov, "vault_ref", ctype)
                needle = f"secrets.{name}" if f"secrets.{name}" in value else name
                out.append(model.make_entry(
                    identity=model.identity_id(prov, name), component=component, provider=prov, ctype=ctype,
                    name=name, storage="vault_ref", resources=resources, federation_available=fed,
                    federation_reason=reason,
                    evidence=[{"file": rel_path, "line": (lf.find(needle, job_line) if origin == "job" else lf.find(needle)) or job_line,
                               "locator": loc}],
                ))
            if refs or model.is_reference(value):
                continue
            if parent_key in ("env", "with", "credentials") and key is not None and model.literal_is_secret(key, value):
                fmt = model.classify_literal(value)
                prov = model.infer_provider(key, [])
                if prov == "unknown":
                    prov = model.FORMAT_PROVIDER.get(fmt["class"], "unknown")
                ctype = model.classify_type(key)
                if ctype == "unknown":
                    ctype = model.FORMAT_TYPE.get(fmt["class"], "unknown")
                named = parent_key == "env"
                name = key if named else f"{component['id']}:{loc}"
                ident = model.identity_id(prov, key) if named else f"{prov}:{component['id']}:{loc}"
                fed, reason = model.federation_context(KIND, prov, "inline", ctype)
                out.append(model.make_entry(
                    identity=ident, component=component, provider=prov, ctype=ctype, name=name, storage="inline",
                    fmt=fmt, resources=resources, federation_available=fed, federation_reason=reason,
                    evidence=[{"file": rel_path, "line": (lf.find(f"{key}:", job_line) if origin == "job" else lf.find(f"{key}:")) or job_line,
                               "locator": loc}],
                ))
            elif key == "run":
                for j, tok in enumerate(t for t in _RUN_TOKEN_SPLIT.split(value) if t):
                    fmt = model.classify_known_shape(tok)
                    if fmt is None or fmt["class"] in ("bearer_literal", "basic_auth_literal"):
                        continue
                    prov = model.FORMAT_PROVIDER.get(fmt["class"], "unknown")
                    ctype = model.FORMAT_TYPE.get(fmt["class"], "unknown")
                    out.append(model.make_entry(
                        identity=f"{prov}:{component['id']}:{loc}", component=component, provider=prov, ctype=ctype,
                        name=f"{component['id']}:{loc}", storage="inline", fmt=fmt, resources=resources,
                        evidence=[{"file": rel_path, "line": line_of("run:"), "locator": loc}],
                    ))
    return out
