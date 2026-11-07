"""docker-compose parser (compose.yaml / docker-compose*.yml).

Pure: ``parse_compose(rel_path, text) -> (entries, warnings)``. Reads, per
service: ``environment`` (map and list forms), ``env_file``, ``secrets``
(service references + top-level definitions) and ``build.args``. Literal
values are inspected only to classify their shape and are then dropped; the
contents of ``secrets.*.file`` targets are never read.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any

import yaml

from .. import model
from .common import LineFinder, merge_entries

KIND = "compose_service"
_FILE_RE = re.compile(r"^(docker-)?compose(\.[A-Za-z0-9_.-]+)?\.ya?ml$")
_NON_ENV = {"override", "local", "example", "sample", "template", "base", "common"}
# ${VAR}, ${VAR:-default}, ${VAR-default}, ${VAR:?err}, ${VAR:+alt}, $VAR  ($$ is an escape)
_INTERP = re.compile(r"(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])([^}]*))?\}|(?<!\$)\$([A-Za-z_][A-Za-z0-9_]*)")


def is_compose_file(rel_path: str) -> bool:
    return bool(_FILE_RE.match(posixpath.basename(rel_path)))


def _environment_of(rel_path: str) -> str | None:
    m = _FILE_RE.match(posixpath.basename(rel_path))
    if not m or not m.group(2):
        return None
    parts = [p for p in m.group(2).strip(".").lower().split(".") if p]
    if not parts or any(p in _NON_ENV for p in parts):
        return None
    return parts[0]


def _interp(value: str) -> tuple[list[str], list[str], bool]:
    """-> (referenced names, default/alt literals, whole value is one interpolation)."""
    names, defaults = [], []
    whole = False
    for m in _INTERP.finditer(value):
        n = m.group(1) or m.group(4)
        if n not in names:
            names.append(n)
        if m.group(2) and m.group(2).lstrip(":") in ("-", "+") and m.group(3):
            defaults.append(m.group(3))
        if m.span() == (0, len(value.strip())) and value == value.strip():
            whole = True
    return names, defaults, whole


_HOST = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*(?::\d{1,5})?$")


def _looks_like_host(value: str) -> bool:
    """Lowercase host name that is dotted or carries a numeric port (e.g. db.internal, cache:6379)."""
    v = value.strip()
    return bool(_HOST.match(v)) and ("." in v or ":" in v)


_KEY_FILE_EXT = (".json", ".pem", ".key", ".p12", ".pfx", ".crt", ".jks")


def _looks_like_key_file(value: str) -> bool:
    """A filesystem path (absolute, relative or with a key-file extension); never a URL or a bare host name."""
    v = value.strip()
    if not v or "://" in v or any(c.isspace() for c in v):
        return False
    if v.startswith(("/", "./", "../", "~/")) or re.match(r"^[A-Za-z]:\\", v):
        return True
    return "/" in v or v.lower().endswith(_KEY_FILE_EXT)


def _pairs(obj: Any) -> list[tuple[str, Any]]:
    """environment / build.args in map or list form -> [(key, value-or-None)]."""
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k in obj:
            out.append((str(k), obj[k]))
    elif isinstance(obj, list):
        for item in obj:
            if not isinstance(item, str):
                continue
            k, eq, v = item.partition("=")
            out.append((k.strip(), v if eq else None))
    return out


def parse_compose(rel_path: str, text: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        return [], [{"file": rel_path, "message": f"invalid YAML near line {mark.line + 1 if mark else '?'}"}]
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict):
        return [], []
    lf = LineFinder(text)
    services_line = lf.find(r"^services:\s*(#.*)?$", regex=True) or 1
    top_secrets = doc.get("secrets") if isinstance(doc.get("secrets"), dict) else {}
    env_name = _environment_of(rel_path)
    base_dir = posixpath.dirname(rel_path)
    warnings: list[dict[str, str]] = []
    entries: list[dict[str, Any]] = []

    for svc in sorted(doc["services"], key=str):
        s = doc["services"][svc]
        if not isinstance(s, dict):
            continue
        svc = str(svc)
        component = model.make_component(KIND, svc, rel_path)
        svc_line = lf.find(rf"^\s+['\"]?{re.escape(svc)}['\"]?:\s*(#.*)?$", services_line, regex=True) or services_line
        image = s.get("image") if isinstance(s.get("image"), str) else None
        resources = []
        if image:
            resources.append({"kind": "image", "value": image})
        if env_name:
            resources.append({"kind": "environment", "value": env_name})
        context = [svc, image or ""]
        raw: list[dict[str, Any]] = []

        def add(name, storage, locator, hint, *, fmt=None, identity=None, ctype=None, provider=None):
            prov = provider or model.infer_provider(name, context)
            if prov == "unknown" and fmt is not None:
                prov = model.FORMAT_PROVIDER.get(fmt["class"], "unknown")
            t = ctype or model.classify_type(name)
            if t == "unknown" and fmt is not None:
                t = model.FORMAT_TYPE.get(fmt["class"], "unknown")
            fed, reason = model.federation_context(KIND, prov, storage, t)
            raw.append(model.make_entry(
                identity=identity or model.identity_id(prov, name), component=component, provider=prov, ctype=t,
                name=name, storage=storage, fmt=fmt, resources=resources, federation_available=fed,
                federation_reason=reason,
                evidence=[{"file": rel_path, "line": lf.find(hint, svc_line) or svc_line, "locator": locator}],
            ))

        def read_vars(pairs, where):
            for k, v in pairs:
                loc = f"services.{svc}.{where}.{k}"
                if v is None:  # passthrough from the host environment
                    if model.is_credential_name(k):
                        add(k, "env", loc, k)
                    continue
                if not isinstance(v, str):
                    continue  # numbers / booleans are configuration
                names, defaults, whole = _interp(v)
                secret_default = next((d for d in defaults if model.literal_is_secret(k, d)), None)
                if secret_default is not None:
                    add(k, "inline", loc, k, fmt=model.classify_literal(secret_default))
                    continue
                if names:
                    if model.url_has_password(_INTERP.sub("", v)):
                        add(k, "inline", loc, k, fmt={"class": "connection_string_with_password", "prefix": None})
                    elif model.is_credential_name(k):
                        name = names[0] if whole and len(names) == 1 else k
                        add(name, "env", loc, k, ctype=model.classify_type(k) if model.classify_type(name) == "unknown" else None)
                    else:
                        for n in names:
                            if model.is_credential_name(n):
                                add(n, "env", loc, k)
                    continue
                h = model.url_host(v)
                if h:
                    resources.append({"kind": "host", "value": h})
                if _looks_like_host(v):
                    resources.append({"kind": "host", "value": v.strip().split(":")[0]})
                    continue  # a host name (optionally with port) is configuration, not a credential (D-049)
                if model.literal_is_secret(k, v):
                    add(k, "inline", loc, k, fmt=model.classify_literal(v))
                elif model.is_credential_name(k) and _looks_like_key_file(v):
                    # credential-named key holding a key-file path (e.g. GOOGLE_APPLICATION_CREDENTIALS): the credential
                    # lives outside the file -> a reference (D-024). Passwordless URLs and host names are configuration (D-049).
                    add(k, "env", loc, k)

        read_vars(_pairs(s.get("environment")), "environment")
        build = s.get("build")
        if isinstance(build, dict):
            read_vars(_pairs(build.get("args")), "build.args")

        # env_file: one identity per referenced file (contents are a .env declaration surface)
        env_files = s.get("env_file")
        if isinstance(env_files, (str, dict)):
            env_files = [env_files]
        for i, ef in enumerate(env_files or []):
            path = ef.get("path") if isinstance(ef, dict) else ef
            if not isinstance(path, str) or not path.strip():
                continue
            norm = posixpath.normpath(posixpath.join(base_dir, path))
            add(f"env_file:{norm}", "env", f"services.{svc}.env_file[{i}]", path,
                identity=f"local:env_file:{norm}", provider="local", ctype="unknown")

        # secrets: service references resolved against top-level definitions
        for i, ref in enumerate(s.get("secrets") or []):
            name = ref.get("source") if isinstance(ref, dict) else ref
            if not isinstance(name, str):
                continue
            definition = top_secrets.get(name) if isinstance(top_secrets.get(name), dict) else {}
            if isinstance(definition.get("environment"), str):
                storage, src = "env", definition["environment"]
            else:
                storage, src = "vault_ref", name  # file / external: contents never read
            if name not in top_secrets:
                warnings.append({"file": rel_path, "message": f"service '{svc}' references undefined secret '{name}'"})
            ctype = model.classify_type(src) if model.classify_type(src) != "unknown" else model.classify_type(name)
            add(name, storage, f"services.{svc}.secrets[{i}]", name, ctype=ctype if ctype != "unknown" else "password")

        final = model.sort_resources(resources)
        for e in raw:
            e["resources"] = final
        entries += raw
    return merge_entries(entries), warnings
