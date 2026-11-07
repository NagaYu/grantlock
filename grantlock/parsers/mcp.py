"""MCP configuration parser (``mcpServers`` / ``servers``).

Pure: ``parse_mcp(rel_path, text) -> (entries, warnings)``. Literal secret
values are inspected only to classify their shape and are then dropped; no
value, slice or hash of a value is ever placed in the output.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .. import model
from .common import LineFinder, load_jsonc, merge_entries

KIND = "mcp_server"

_SCOPE_FLAGS = {"--scopes": "scope", "--scope": "scope", "--role": "role", "--toolsets": "toolset",
                "--permissions": "scope"}
_CRED_FLAG = re.compile(r"^--?(api[-_]?key|token|access[-_]?token|auth[-_]?token|password|secret|"
                        r"client[-_]?secret|pat|key)$", re.IGNORECASE)
_DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network",
                       "--env-file", "-w", "--workdir", "-u", "--user", "--entrypoint", "--mount",
                       "--platform", "--label", "-l", "--add-host", "--cpus", "-m", "--memory"}
_AUTH_HEADER = re.compile(r"^(authorization|proxy-authorization|cookie|x-api-key|api-key|apikey|"
                          r"x-[a-z0-9-]*(token|key|secret|auth)[a-z0-9-]*|[a-z0-9-]*-token)$", re.IGNORECASE)


def is_mcp_config(rel_path: str, doc: Any) -> bool:
    if not isinstance(doc, dict):
        return False
    if isinstance(doc.get("mcpServers"), dict):
        return True
    base = posixpath.basename(rel_path).lower()
    return "mcp" in base and isinstance(doc.get("servers"), dict)


def _servers(doc: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if isinstance(doc.get("mcpServers"), dict):
        return "mcpServers", doc["mcpServers"]
    return "servers", doc["servers"]


def _split_scopes(value: str) -> list[str]:
    return [t for t in re.split(r"[\s,]+", value.strip()) if t]


def _scope_tokens(kind: str, value: str) -> list[str]:
    toks = _split_scopes(value)
    if kind == "toolset":
        return ["toolset:*" if t.lower() == "all" else f"toolset:{t}" for t in toks]
    if kind == "role":
        return [f"role:{t}" for t in toks]
    return toks


def _scope_kind_for_name(name: str) -> str:
    n = name.upper()
    if n.endswith("TOOLSETS"):
        return "toolset"
    if n.endswith("ROLE"):
        return "role"
    return "scope"


def _package_resources(command: str, args: list[str]) -> list[dict[str, str]]:
    cmd = posixpath.basename(command or "").lower()
    res: list[dict[str, str]] = []
    if cmd in {"npx", "bunx", "pnpx", "uvx", "pipx"} or (cmd in {"pnpm", "npm", "yarn"} and args[:1] in (["dlx"], ["exec"])):
        rest = args[1:] if cmd in {"pnpm", "npm", "yarn"} else args
        if cmd == "pipx" and rest[:1] == ["run"]:
            rest = rest[1:]
        for a in rest:
            if a.startswith("-"):
                continue
            res.append({"kind": "package", "value": a})
            break
    elif cmd in {"docker", "podman"} and "run" in args:
        it = iter(args[args.index("run") + 1:])
        for a in it:
            if a in _DOCKER_VALUE_FLAGS:
                next(it, None)
                continue
            if a.startswith("-"):
                continue
            res.append({"kind": "image", "value": a})
            break
    return res


def parse_mcp(rel_path: str, text: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    warnings: list[dict[str, str]] = []
    try:
        doc = load_jsonc(text)
    except ValueError as exc:  # json.JSONDecodeError is a ValueError
        return [], [{"file": rel_path, "message": f"invalid JSON: line {getattr(exc, 'lineno', '?')}"}]
    if not is_mcp_config(rel_path, doc):
        return [], []
    root_key, servers = _servers(doc)
    lf = LineFinder(text)
    root_line = lf.find(f'"{root_key}"') or 1
    entries: list[dict[str, Any]] = []
    for srv_name in sorted(servers):
        srv = servers[srv_name]
        if not isinstance(srv, dict):
            warnings.append({"file": rel_path, "message": f"server '{srv_name}' is not an object"})
            continue
        entries.extend(_parse_server(rel_path, root_key, srv_name, srv, lf, root_line))
    return merge_entries(entries), warnings


def _parse_server(rel_path, root_key, srv_name, srv, lf: LineFinder, root_line) -> list[dict[str, Any]]:
    component = model.make_component(KIND, srv_name, rel_path)
    srv_line = lf.find(f'"{srv_name}"', root_line) or root_line
    command = srv.get("command") if isinstance(srv.get("command"), str) else ""
    args = [a for a in srv.get("args", []) if isinstance(a, str)] if isinstance(srv.get("args"), list) else []
    url = srv.get("url") if isinstance(srv.get("url"), str) else (srv.get("serverUrl") if isinstance(srv.get("serverUrl"), str) else "")
    env = srv.get("env") if isinstance(srv.get("env"), dict) else {}
    headers = srv.get("headers") if isinstance(srv.get("headers"), dict) else {}
    oauth = srv.get("oauth") if isinstance(srv.get("oauth"), dict) else {}

    resources: list[dict[str, str]] = _package_resources(command, args)
    host = model.url_host(url) if url else None
    if host:
        resources.append({"kind": "host", "value": host})
    context = [srv_name, command, " ".join(args), url or ""] + [r["value"] for r in resources]

    # ---- scopes -----------------------------------------------------------
    scopes: list[str] = []
    for k in sorted(env):
        v = env[k]
        if isinstance(v, str) and model.is_scope_name(k) and not model.is_reference(v) and not model.literal_is_secret(None, v) and v.strip():
            scopes += _scope_tokens(_scope_kind_for_name(k), v)
    for i, a in enumerate(args):
        flag, _, inline_val = a.partition("=")
        if flag in _SCOPE_FLAGS:
            val = inline_val if inline_val else (args[i + 1] if i + 1 < len(args) else "")
            if val and not model.is_reference(val):
                scopes += _scope_tokens(_SCOPE_FLAGS[flag], val)
    oscopes = oauth.get("scopes", oauth.get("scope"))
    if isinstance(oscopes, list):
        scopes += [s for s in oscopes if isinstance(s, str)]
    elif isinstance(oscopes, str):
        scopes += _split_scopes(oscopes)
    scopes_known = bool(scopes)
    scope_source = "declared" if scopes_known else "unknown"

    raw: list[dict[str, Any]] = []

    def add(name: str, storage: str, locator: str, line_hint, fmt=None, identity: str | None = None,
            ctype: str | None = None, provider: str | None = None):
        prov = provider or model.infer_provider(name, context)
        if prov == "unknown" and fmt is not None:
            prov = model.FORMAT_PROVIDER.get(fmt["class"], "unknown")
        t = ctype or model.classify_type(name)
        if t == "unknown" and fmt is not None:
            t = model.FORMAT_TYPE.get(fmt["class"], "unknown")
        fed, reason = model.federation_context(KIND, prov, storage, t)
        hints = [line_hint] if isinstance(line_hint, str) else list(line_hint)
        line = lf.find_chain(hints, srv_line) or srv_line
        raw.append(model.make_entry(
            identity=identity or model.identity_id(prov, name),
            component=component, provider=prov, ctype=t, name=name, storage=storage, fmt=fmt,
            scopes=scopes, scopes_known=scopes_known, scope_source=scope_source,
            resources=resources, federation_available=fed, federation_reason=reason,
            evidence=[{"file": rel_path, "line": line, "locator": locator}],
        ))

    base = f"{root_key}.{srv_name}"

    # ---- env --------------------------------------------------------------
    for k in sorted(env):
        v = env[k]
        if not isinstance(v, str) or model.is_scope_name(k):
            continue
        loc = f"{base}.env.{k}"
        if model.literal_is_secret(k, v):
            add(k, "inline", loc, ['"env"', f'"{k}"'], fmt=model.classify_literal(v))
            continue
        refs = model.referenced_names(v)
        if model.is_credential_name(k):
            # `"GITHUB_PERSONAL_ACCESS_TOKEN": "${GH_PAT}"` -> the source variable is GH_PAT
            name = refs[0] if len(refs) == 1 and model.is_reference(v) else k
            add(name, "env", loc, ['"env"', f'"{k}"'], ctype=model.classify_type(k) if name != k and model.classify_type(name) == "unknown" else None)
            continue
        for r in refs:
            if model.is_credential_name(r):
                add(r, "env", loc, ['"env"', f'"{k}"'])
        h = model.url_host(v) if not refs else None
        if h:
            resources.append({"kind": "host", "value": h})

    # ---- headers ----------------------------------------------------------
    for h in sorted(headers):
        v = headers[h]
        if not isinstance(v, str):
            continue
        loc = f"{base}.headers.{h}"
        refs = model.referenced_names(v)
        if refs and not model.literal_is_secret(h, v):
            for r in refs:
                add(r, "env", loc, f'"{h}"', ctype=None if model.classify_type(r) != "unknown" else "token")
        elif model.literal_is_secret(h, v) or (_AUTH_HEADER.match(h) and not model.is_placeholder(v)):
            fmt = model.classify_literal(v)
            prov = model.infer_provider(h, context)
            if prov == "unknown":
                prov = model.FORMAT_PROVIDER.get(fmt["class"], "unknown")
            add(f"{srv_name}.headers.{h}", "inline", loc, f'"{h}"', fmt=fmt, provider=prov,
                identity=f"{prov}:{component['id']}:headers.{h}",
                ctype=model.FORMAT_TYPE.get(fmt["class"], "token"))

    # ---- args -------------------------------------------------------------
    skip_next = False
    for i, a in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        flag, eq, inline_val = a.partition("=")
        if _CRED_FLAG.match(flag):
            val = inline_val if eq else (args[i + 1] if i + 1 < len(args) else "")
            skip_next = not eq
            loc = f"{base}.args[{i}]"
            refs = model.referenced_names(val)
            if refs and model.is_reference(val):
                for r in refs:
                    add(r, "env", loc, flag, ctype=None if model.classify_type(r) != "unknown" else "token")
            elif val and not model.is_placeholder(val):
                fmt = model.classify_literal(val)
                prov = model.infer_provider(flag, context)
                if prov == "unknown":
                    prov = model.FORMAT_PROVIDER.get(fmt["class"], "unknown")
                add(f"{srv_name}.args.{flag.lstrip('-')}", "inline", loc, flag, fmt=fmt, provider=prov,
                    identity=f"{prov}:{component['id']}:args.{flag.lstrip('-')}",
                    ctype=model.FORMAT_TYPE.get(fmt["class"], "api_key"))
            continue
        if flag in _SCOPE_FLAGS:
            skip_next = not eq
            continue
        loc = f"{base}.args[{i}]"
        if model.literal_is_secret(None, a):
            fmt = model.classify_literal(a)
            prov = model.infer_provider("", context)
            if prov == "unknown":
                prov = model.FORMAT_PROVIDER.get(fmt["class"], "unknown")
            h = model.url_host(a)
            if h:
                resources.append({"kind": "host", "value": h})
            add(f"{srv_name}.args[{i}]", "inline", loc, "args", fmt=fmt, provider=prov,
                identity=f"{prov}:{component['id']}:args[{i}]",
                ctype=model.FORMAT_TYPE.get(fmt["class"], "unknown"))
            continue
        for r in model.referenced_names(a):
            if model.is_credential_name(r):
                add(r, "env", loc, "args")
        h = model.url_host(a) if a.lower().startswith(("http://", "https://", "postgres", "mysql", "mongodb", "redis")) else None
        if h:
            resources.append({"kind": "host", "value": h})

    # ---- url query parameters --------------------------------------------
    if url:
        for qk, qv in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            loc = f"{base}.url?{qk}"
            if model.literal_is_secret(qk, qv):
                fmt = model.classify_literal(qv)
                prov = model.infer_provider(qk, context)
                add(f"{srv_name}.url.{qk}", "inline", loc, '"url"', fmt=fmt, provider=prov,
                    identity=f"{prov}:{component['id']}:url.{qk}",
                    ctype=model.FORMAT_TYPE.get(fmt["class"], "api_key"))
            else:
                for r in model.referenced_names(qv):
                    add(r, "env", loc, '"url"')

    # ---- oauth block literals ---------------------------------------------
    for ok in sorted(oauth):
        ov = oauth[ok]
        if isinstance(ov, str) and ok not in ("scopes", "scope") and model.is_credential_name(ok):
            loc = f"{base}.oauth.{ok}"
            if model.literal_is_secret(ok, ov):
                fmt = model.classify_literal(ov)
                prov = model.infer_provider(ok, context)
                add(f"{srv_name}.oauth.{ok}", "inline", loc, f'"{ok}"', fmt=fmt, provider=prov,
                    identity=f"{prov}:{component['id']}:oauth.{ok}", ctype="oauth")
            else:
                for r in model.referenced_names(ov):
                    add(r, "env", loc, f'"{ok}"', ctype="oauth")

    # ---- remote server without static credential: delegated OAuth ----------
    if url and host and not raw and srv.get("type") != "stdio":
        prov = model.infer_provider("", context)
        add(f"oauth:{host}", "vault_ref", f"{base}.url", '"url"', provider=prov,
            identity=f"{prov}:oauth:{host}", ctype="oauth")

    # resources may have grown while reading env/args: apply to every entry
    final_res = model.sort_resources(resources)
    for e in raw:
        e["resources"] = final_res
    return raw
