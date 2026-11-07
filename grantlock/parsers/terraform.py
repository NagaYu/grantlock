"""Terraform (.tf) parser, limited to identity-relevant resources.

Not a full HCL implementation: a tolerant structural reader (nested blocks,
quoted strings with interpolation, heredocs, lists, comments) feeding
resource-specific extractors. Anything it does not understand is skipped; a
file it cannot structure at all yields a warning, never an exception.

    load_blocks(rel_path, text) -> (blocks, warnings)   # one file
    build(blocks)               -> (entries, warnings)  # all files, resolved per module directory

Literal values are classified (format class only) and discarded. ``var.*`` and
remote state are not evaluated.
"""

from __future__ import annotations

import json
import posixpath
import re
from dataclasses import dataclass, field
from typing import Any

from .. import model
from .common import merge_entries

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_ENV_SEGMENTS = {"prod", "production", "prd", "live", "staging", "stage", "dev", "development", "test", "qa"}
_PRINCIPAL_REF = re.compile(
    r"\b(aws_iam_role|aws_iam_user|google_service_account|azurerm_user_assigned_identity|azuread_service_principal)\.([A-Za-z0-9_-]+)\b")
_POLICY_DOC_REF = re.compile(r"\bdata\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.json\b")
_VAR_REF = re.compile(r"\bvar\.([A-Za-z_][A-Za-z0-9_-]*)")
_POLICY_REF = re.compile(r"\baws_iam_policy\.([A-Za-z0-9_-]+)\.(arn|id)\b")
_PROVIDER_OF = {"aws_iam_role": "aws", "aws_iam_user": "aws", "google_service_account": "gcp",
                "azurerm_user_assigned_identity": "azure", "azuread_service_principal": "azure"}
CONSUMER_TYPES = {
    "aws_lambda_function", "aws_ecs_task_definition", "aws_iam_instance_profile", "aws_eks_pod_identity_association",
    "aws_codebuild_project", "aws_sfn_state_machine", "aws_batch_compute_environment", "aws_apprunner_service",
    "google_cloud_run_service", "google_cloud_run_v2_service", "google_cloudfunctions_function",
    "google_cloudfunctions2_function", "google_container_node_pool", "google_compute_instance",
    "azurerm_linux_web_app", "azurerm_windows_web_app", "azurerm_container_app", "azurerm_linux_function_app",
    "azurerm_kubernetes_cluster",
}
STATIC_KEY_TYPES = {
    "aws_iam_access_key": ("aws", "api_key"),
    "google_service_account_key": ("gcp", "service_account"),
    "azuread_application_password": ("azure", "oauth"),
    "azuread_service_principal_password": ("azure", "oauth"),
}
POLICY_ATTRS = {"policy", "assume_role_policy", "policy_document"}
# Provider-block credentials (D-041): static attributes -> one long-lived identity per provider block;
# federated forms -> an ephemeral identity.
PROVIDER_CREDENTIALS = {
    "aws": {"provider": "aws", "static": ["access_key", "secret_key"], "static_name": "access_key", "static_type": "api_key",
            "federated_blocks": ["assume_role", "assume_role_with_web_identity"]},
    "google": {"provider": "gcp", "static": ["credentials", "access_token"], "static_name": "credentials",
               "static_type": "service_account",
               "federated_attrs": [("impersonate_service_account", "impersonate_service_account", False)]},
    "azurerm": {"provider": "azure", "static": ["client_secret", "client_certificate_password", "client_certificate_path"],
                "static_name": "client_secret", "static_type": "oauth",
                "federated_attrs": [("use_oidc", "oidc", True), ("use_msi", "msi", True)]},
}


class HCLError(ValueError):
    pass


@dataclass
class Attr:
    name: str
    raw: str
    line: int


@dataclass
class Block:
    type: str
    labels: list[str]
    line: int
    file: str = ""
    attrs: dict[str, Attr] = field(default_factory=dict)
    blocks: list["Block"] = field(default_factory=list)
    raw: str = ""

    def address(self) -> str | None:
        if self.type == "resource" and len(self.labels) == 2:
            return f"{self.labels[0]}.{self.labels[1]}"
        if self.type == "data" and len(self.labels) == 2:
            return f"data.{self.labels[0]}.{self.labels[1]}"
        if self.type == "provider" and self.labels:
            alias = string_value(self.attrs["alias"].raw) if "alias" in self.attrs else None
            return f"provider.{self.labels[0]}" + (f".{alias}" if alias else "")
        if self.type == "variable" and self.labels:
            return f"var.{self.labels[0]}"
        if self.type == "locals":
            return "locals"
        if self.type == "module" and self.labels:
            return f"module.{self.labels[0]}"
        return None


# ------------------------------------------------------------------ reader --

class _Reader:
    def __init__(self, text: str):
        self.t = text
        self.i = 0
        self.n = len(text)

    def line(self) -> int:
        return self.t.count("\n", 0, self.i) + 1

    def skip_ws(self, newlines: bool = True) -> None:
        while self.i < self.n:
            c = self.t[self.i]
            if c in " \t\r" or (newlines and c == "\n"):
                self.i += 1
            elif c == "#" or self.t.startswith("//", self.i):
                j = self.t.find("\n", self.i)
                self.i = self.n if j < 0 else j
            elif self.t.startswith("/*", self.i):
                j = self.t.find("*/", self.i + 2)
                if j < 0:
                    raise HCLError("unterminated comment")
                self.i = j + 2
            else:
                break

    def string(self) -> str:
        """Consume a quoted string (with ${...} interpolation); return its raw text."""
        start = self.i
        assert self.t[self.i] == '"'
        self.i += 1
        depth = 0
        while self.i < self.n:
            c = self.t[self.i]
            if c == "\\":
                self.i += 2
                continue
            if self.t.startswith("${", self.i) or self.t.startswith("%{", self.i):
                depth += 1
                self.i += 2
                continue
            if c == "}" and depth:
                depth -= 1
            elif c == '"' and not depth:
                self.i += 1
                return self.t[start:self.i]
            elif c == "\n" and not depth:
                raise HCLError("newline in string")
            self.i += 1
        raise HCLError("unterminated string")

    def heredoc(self) -> str:
        m = re.compile(r"<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\n").match(self.t, self.i)
        if not m:
            raise HCLError("bad heredoc")
        marker = m.group(1)
        end = re.compile(rf"^[ \t]*{re.escape(marker)}[ \t]*$", re.M).search(self.t, m.end())
        if not end:
            raise HCLError("unterminated heredoc")
        start = self.i
        self.i = end.end()
        return self.t[start:self.i]

    def expression(self) -> str:
        start = self.i
        depth = 0
        while self.i < self.n:
            c = self.t[self.i]
            if c == '"':
                self.string()
                continue
            if self.t.startswith("<<", self.i) and re.match(r"<<-?[A-Za-z_]", self.t[self.i:self.i + 4]):
                self.heredoc()
                continue
            if c == "#" or self.t.startswith("//", self.i):
                if depth == 0:
                    break  # trailing line comment ends the expression
                j = self.t.find("\n", self.i)
                self.i = self.n if j < 0 else j
                continue
            if self.t.startswith("/*", self.i):
                j = self.t.find("*/", self.i + 2)
                if j < 0:
                    raise HCLError("unterminated comment")
                self.i = j + 2
                continue
            if c in "([{":
                depth += 1
            elif c in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif c == "\n" and depth == 0:
                break
            self.i += 1
        if depth:
            raise HCLError("unbalanced brackets")
        return self.t[start:self.i].strip()

    def body(self, file: str, closing: bool) -> tuple[dict[str, Attr], list[Block]]:
        attrs: dict[str, Attr] = {}
        blocks: list[Block] = []
        while True:
            self.skip_ws()
            if self.i >= self.n:
                if closing:
                    raise HCLError("unexpected end of file")
                return attrs, blocks
            if self.t[self.i] == "}":
                if not closing:
                    raise HCLError("unexpected '}'")
                self.i += 1
                return attrs, blocks
            m = _IDENT.match(self.t, self.i)
            if not m:
                raise HCLError(f"unexpected character {self.t[self.i]!r}")
            name = m.group(0)
            line = self.line()
            self.i = m.end()
            self.skip_ws(newlines=False)
            if self.t.startswith("=", self.i) and not self.t.startswith("==", self.i):
                self.i += 1
                self.skip_ws(newlines=False)
                attrs[name] = Attr(name, self.expression(), line)
                continue
            labels = []
            while self.i < self.n and self.t[self.i] != "{":
                if self.t[self.i] == '"':
                    labels.append(string_value(self.string()) or "")
                else:
                    lm = _IDENT.match(self.t, self.i)
                    if not lm:
                        raise HCLError(f"bad block header for {name}")
                    labels.append(lm.group(0))
                    self.i = lm.end()
                self.skip_ws(newlines=False)
            if self.i >= self.n:
                raise HCLError("missing '{'")
            bstart = self.i
            self.i += 1
            a, b = self.body(file, closing=True)
            blk = Block(name, labels, line, file, a, b, self.t[bstart:self.i])
            blocks.append(blk)


def string_value(raw: str) -> str | None:
    """Value of a plain quoted string or heredoc without interpolation, else None."""
    raw = raw.strip()
    if raw.startswith("<<"):
        m = re.match(r"<<-?([A-Za-z_][A-Za-z0-9_]*)[ \t]*\n(.*)\n[ \t]*\1[ \t]*$", raw, re.S)
        if not m or "${" in m.group(2):
            return None
        return m.group(2)
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"' and "${" not in raw and '"' not in raw[1:-1].replace('\\"', ""):
        try:
            return json.loads(raw)
        except ValueError:
            return raw[1:-1]
    return None


def string_list(raw: str) -> list[str]:
    raw = raw.strip()
    if raw.startswith("["):
        return [json.loads(f'"{s}"') if "\\" in s else s for s in re.findall(r'"((?:[^"\\]|\\.)*)"', raw)]
    v = string_value(raw)
    return [v] if v is not None else []


def load_blocks(rel_path: str, text: str) -> tuple[list[Block], list[dict[str, str]]]:
    r = _Reader(text)
    try:
        _, blocks = r.body(rel_path, closing=False)
    except HCLError as exc:
        return [], [{"file": rel_path, "message": f"Terraform structure not understood near line {r.line()}: {exc}"}]
    return blocks, []


# ------------------------------------------------------------------ policies --

def _policy_statements_from_text(text: str) -> list[dict[str, Any]]:
    """Statements of a JSON policy (heredoc / string) or, failing that, a jsonencode() body."""
    body = text.strip()
    if body.startswith("<<"):
        body = re.sub(r"^<<-?[A-Za-z_][A-Za-z0-9_]*[ \t]*\n|\n[ \t]*[A-Za-z_][A-Za-z0-9_]*[ \t]*$", "", body)
    elif body.startswith('"'):
        sv = string_value(body)
        body = sv if sv is not None else body
    try:
        doc = json.loads(body)
        st = doc.get("Statement") if isinstance(doc, dict) else None
        st = [st] if isinstance(st, dict) else st
        if isinstance(st, list):
            return [s for s in st if isinstance(s, dict)]
    except ValueError:
        pass
    # jsonencode({...}) / templated JSON: per-statement regex over `{ ... }` chunks
    out = []
    for chunk in re.split(r"\}\s*,\s*\{", body):
        eff = re.search(r'"?Effect"?\s*[:=]\s*"(Allow|Deny)"', chunk)
        st: dict[str, Any] = {"Effect": eff.group(1) if eff else "Allow"}
        for key in ("Action", "NotAction", "Resource", "NotResource"):
            m = re.search(rf'"?\b{key}"?\s*[:=]\s*(\[[^\]]*\]|"[^"]*")', chunk)
            if m:
                st[key] = re.findall(r'"([^"]*)"', m.group(1))
        if len(st) > 1:
            out.append(st)
    return out


def _statements_from_doc(blk: Block) -> list[dict[str, Any]]:
    out = []
    for s in blk.blocks:
        if s.type != "statement":
            continue
        eff = string_value(s.attrs["effect"].raw) if "effect" in s.attrs else "Allow"
        st: dict[str, Any] = {"Effect": eff or "Allow"}
        for attr, key in (("actions", "Action"), ("not_actions", "NotAction"), ("resources", "Resource"),
                          ("not_resources", "NotResource")):
            if attr in s.attrs:
                st[key] = string_list(s.attrs[attr].raw)
        out.append(st)
    return out


def _scopes(statements: list[dict[str, Any]]) -> list[str]:
    out = set()
    for st in statements:
        if str(st.get("Effect", "Allow")) != "Allow":
            continue
        for key, prefix in (("Action", "iam:action:"), ("NotAction", "iam:notaction:"), ("Resource", "iam:resource:"),
                            ("NotResource", "iam:notresource:")):
            v = st.get(key)
            for x in ([v] if isinstance(v, str) else (v or [])):
                if isinstance(x, str) and x:
                    out.add(prefix + x)
    return sorted(out)


# ------------------------------------------------------------------ build --

def _env_resources(path: str) -> list[dict[str, str]]:
    segs = [s.lower() for s in path.split("/")[:-1]] + [posixpath.splitext(posixpath.basename(path))[0].lower()]
    return [{"kind": "environment", "value": s} for s in segs if s in _ENV_SEGMENTS][:1]


def build(blocks: list[Block]) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    warnings: list[dict[str, str]] = []
    entries: list[dict[str, Any]] = []
    modules: dict[str, list[Block]] = {}
    for b in blocks:
        modules.setdefault(posixpath.dirname(b.file), []).append(b)
    for mod in sorted(modules):
        entries += _build_module(mod, modules[mod], warnings)
    return merge_entries(entries), warnings


def _build_module(mod: str, blocks: list[Block], warnings) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    by_addr: dict[str, Block] = {}
    for b in blocks:
        a = b.address()
        if a and a not in ("locals",):
            by_addr.setdefault(a, b)
    prefix = f"{mod}//" if mod else ""
    oidc = any(b.type == "resource" and b.labels[:1] in (["aws_iam_openid_connect_provider"], ["google_iam_workload_identity_pool_provider"])
               for b in blocks)

    def ident(provider: str, address: str) -> str:
        return f"{provider}:terraform:{prefix}{address}"

    def principal_of(raw: str) -> tuple[str, str] | None:
        m = _PRINCIPAL_REF.search(raw)
        if not m:
            return None
        return _PROVIDER_OF[m.group(1)], f"{m.group(1)}.{m.group(2)}"

    def comp(blk: Block, kind: str = "terraform") -> dict[str, str]:
        return model.make_component(kind, blk.address() or blk.type, blk.file)

    def res_of(blk: Block, extra=()) -> list[dict[str, str]]:
        return _env_resources(blk.file) + list(extra)

    def add(blk, kind, identity, provider, ctype, name, storage, *, scopes=(), known=False, source="unknown",
            lifespan=None, fmt=None, fed=(False, None), extra_res=(), line=None, locator=None):
        out.append(model.make_entry(
            identity=identity, component=comp(blk, kind), provider=provider, ctype=ctype, name=name, storage=storage,
            fmt=fmt, scopes=scopes, scopes_known=known, scope_source=source, resources=res_of(blk, extra_res),
            lifespan=lifespan, federation_available=fed[0], federation_reason=fed[1],
            evidence=[{"file": blk.file, "line": line or blk.line, "locator": locator or (blk.address() or blk.type)}]))

    def policy_scopes(blk: Block, attr: str) -> tuple[list[str], Block]:
        """-> (scopes, component block where the statements are written)."""
        raw = blk.attrs[attr].raw
        m = _POLICY_DOC_REF.search(raw)
        if m and f"data.aws_iam_policy_document.{m.group(1)}" in by_addr:
            doc = by_addr[f"data.aws_iam_policy_document.{m.group(1)}"]
            return _scopes(_statements_from_doc(doc)), doc
        return _scopes(_policy_statements_from_text(raw)), blk

    resources = [b for b in blocks if b.type == "resource" and len(b.labels) == 2]

    # principals --------------------------------------------------------------
    for b in resources:
        rtype, addr = b.labels[0], b.address()
        if rtype == "aws_iam_role":
            trust = b.attrs.get("assume_role_policy").raw if "assume_role_policy" in b.attrs else ""
            m = _POLICY_DOC_REF.search(trust)
            if m and f"data.aws_iam_policy_document.{m.group(1)}" in by_addr:
                trust = by_addr[f"data.aws_iam_policy_document.{m.group(1)}"].raw
            web = "AssumeRoleWithWebIdentity" in trust or "Federated" in trust or "federated" in trust
            extra = [{"kind": "cloud_resource", "value": "trust:web-identity"}] if web else []
            managed = [f"iam:managed:{x.rsplit('/', 1)[-1]}" for x in string_list(b.attrs["managed_policy_arns"].raw)] if "managed_policy_arns" in b.attrs else []
            inline_scopes: list[str] = []
            for ib in b.blocks:
                if ib.type == "inline_policy" and "policy" in ib.attrs:
                    inline_scopes += policy_scopes(ib, "policy")[0]
            sc = sorted(set(managed + inline_scopes))
            add(b, "terraform", ident("aws", addr), "aws", "service_account", addr, "federated", scopes=sc, known=bool(sc),
                source="declared" if sc else "unknown", lifespan="ephemeral", extra_res=extra)
        elif rtype == "aws_iam_user":
            add(b, "terraform", ident("aws", addr), "aws", "service_account", addr, "vault_ref", lifespan="long_lived")
        elif rtype == "google_service_account":
            add(b, "terraform", ident("gcp", addr), "gcp", "service_account", addr, "vault_ref", lifespan="ephemeral")
        elif rtype == "azurerm_user_assigned_identity":
            add(b, "terraform", ident("azure", addr), "azure", "service_account", addr, "federated", lifespan="ephemeral")

    # policies -> scopes on principals ------------------------------------------
    attachments: dict[str, list[tuple[str, str]]] = {}
    for b in resources:
        rtype = b.labels[0]
        if rtype in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment", "aws_iam_policy_attachment",
                     "aws_iam_group_policy_attachment"):
            arn_raw = b.attrs["policy_arn"].raw if "policy_arn" in b.attrs else ""
            principals = [principal_of(b.attrs[k].raw) for k in ("role", "user", "roles", "users") if k in b.attrs]
            principals = [p for p in principals if p]
            pm = _POLICY_REF.search(arn_raw)
            if pm:
                attachments.setdefault(f"aws_iam_policy.{pm.group(1)}", []).extend(principals)
                continue
            arn = string_value(arn_raw)
            if arn:
                sc = [f"iam:managed:{arn.rsplit('/', 1)[-1]}"]
                for prov, paddr in principals or [("aws", b.address())]:
                    add(b, "terraform", ident(prov, paddr), prov, "service_account", paddr, "federated" if paddr.startswith("aws_iam_role") else "vault_ref",
                        scopes=sc, known=True, source="declared", lifespan="ephemeral" if paddr.startswith("aws_iam_role") else "long_lived",
                        line=b.attrs["policy_arn"].line, locator=f"{b.address()}.policy_arn")
    for b in resources:
        rtype, addr = b.labels[0], b.address()
        if rtype == "aws_iam_policy" and "policy" in b.attrs:
            sc, where = policy_scopes(b, "policy")
            for prov, paddr in attachments.get(addr) or [("aws", addr)]:
                add(where, "terraform", ident(prov, paddr), prov, "service_account", paddr, "federated" if paddr.startswith("aws_iam_role") else "vault_ref",
                    scopes=sc, known=True, source="declared", lifespan="ephemeral" if paddr.startswith("aws_iam_role") else "long_lived",
                    line=b.attrs["policy"].line if where is b else where.line, locator=f"{where.address()}")
        elif rtype in ("aws_iam_role_policy", "aws_iam_user_policy") and "policy" in b.attrs:
            sc, where = policy_scopes(b, "policy")
            p = principal_of(b.attrs.get("role", b.attrs.get("user", Attr("", "", 0))).raw) or ("aws", addr)
            add(where, "terraform", ident(p[0], p[1]), p[0], "service_account", p[1], "federated" if p[1].startswith("aws_iam_role") else "vault_ref",
                scopes=sc, known=True, source="declared", lifespan="ephemeral" if p[1].startswith("aws_iam_role") else "long_lived",
                line=b.attrs["policy"].line if where is b else where.line, locator=f"{where.address()}")
        elif re.match(r"^google_.*_iam_(member|binding)$", rtype) and "role" in b.attrs:
            role = string_value(b.attrs["role"].raw) or b.attrs["role"].raw
            members_raw = " ".join(b.attrs[k].raw for k in ("member", "members") if k in b.attrs)
            p = principal_of(members_raw)
            if p:
                pid, pname = ident(p[0], p[1]), p[1]
            else:
                lits = string_list(b.attrs["members"].raw) if "members" in b.attrs else ([string_value(b.attrs["member"].raw)] if "member" in b.attrs else [])
                lit = next((x for x in lits if x), addr)
                pid, pname = f"gcp:member:{lit}", lit
            add(b, "terraform", pid, "gcp", "service_account", pname, "vault_ref", scopes=[f"role:{role}"], known=True,
                source="declared", lifespan="ephemeral", line=b.attrs["role"].line)
        elif rtype == "azurerm_role_assignment":
            role = string_value(b.attrs["role_definition_name"].raw) if "role_definition_name" in b.attrs else None
            p = principal_of(b.attrs["principal_id"].raw) if "principal_id" in b.attrs else None
            scope_val = string_value(b.attrs["scope"].raw) if "scope" in b.attrs else None
            extra = [{"kind": "cloud_resource", "value": scope_val}] if scope_val else []
            pid, pname = (ident(p[0], p[1]), p[1]) if p else (ident("azure", addr), addr)
            add(b, "terraform", pid, "azure", "service_account", pname, "federated", scopes=[f"role:{role}"] if role else [],
                known=bool(role), source="declared" if role else "unknown", lifespan="ephemeral", extra_res=extra,
                line=b.attrs["role_definition_name"].line if "role_definition_name" in b.attrs else None)

    # static key resources --------------------------------------------------------
    for b in resources:
        rtype, addr = b.labels[0], b.address()
        if rtype in STATIC_KEY_TYPES:
            prov, ctype = STATIC_KEY_TYPES[rtype]
            fed, reason = model.federation_context("terraform", prov, "vault_ref", ctype)
            if fed and oidc:
                reason = reason + " (a federation provider is already defined in this module)"
            p = principal_of(b.raw)
            add(b, "terraform", ident(prov, addr), prov, ctype, addr, "vault_ref", lifespan="long_lived", fed=(fed, reason),
                extra_res=[{"kind": "cloud_resource", "value": p[1]}] if p else [])

    # consumers -----------------------------------------------------------------------
    for b in resources:
        if b.labels[0] in CONSUMER_TYPES:
            seen = set()
            for m in _PRINCIPAL_REF.finditer(b.raw):
                paddr = f"{m.group(1)}.{m.group(2)}"
                if paddr in seen:
                    continue
                seen.add(paddr)
                prov = _PROVIDER_OF[m.group(1)]
                storage = "federated" if m.group(1) in ("aws_iam_role", "azurerm_user_assigned_identity") else "vault_ref"
                add(b, "terraform_workload", ident(prov, paddr), prov, "service_account", paddr, storage,
                    lifespan="ephemeral", locator=f"{b.address()} -> {paddr}")

    # credential variables: declarations and the resources that use them (D-043) --------
    var_blocks = {b.labels[0]: b for b in blocks if b.type == "variable" and b.labels}

    def credential_var(name: str) -> bool:
        vb = var_blocks.get(name)
        sensitive = vb is not None and "sensitive" in vb.attrs and vb.attrs["sensitive"].raw.strip() == "true"
        return model.is_credential_name(name) or sensitive

    for name, vb in sorted(var_blocks.items()):
        if credential_var(name):
            prov, ctype = model.infer_provider(name), model.classify_type(name)
            add(vb, "terraform", ident(prov, f"var.{name}"), prov, ctype, f"var.{name}", "env",
                lifespan=model.lifespan_for("env", ctype))
    for b in blocks:
        if b.type not in ("resource", "module") or not b.labels:
            continue  # provider blocks are covered by their own credential identity (D-041)
        for name in sorted(set(_VAR_REF.findall(b.raw))):
            if credential_var(name):
                prov, ctype = model.infer_provider(name), model.classify_type(name)
                line = next((a.line for a in b.attrs.values() if f"var.{name}" in a.raw), b.line)
                add(b, "terraform_workload", ident(prov, f"var.{name}"), prov, ctype, f"var.{name}", "env",
                    lifespan=model.lifespan_for("env", ctype), line=line, locator=f"{b.address()} -> var.{name}")

    # provider-block credentials (D-041) ------------------------------------------------
    for b in blocks:
        if b.type != "provider" or not b.labels or b.labels[0] not in PROVIDER_CREDENTIALS:
            continue
        spec = PROVIDER_CREDENTIALS[b.labels[0]]
        prov, addr = spec["provider"], b.address()
        statics = [a for a in spec["static"] if a in b.attrs]
        nonliteral = [a for a in statics
                      if not (string_value(b.attrs[a].raw) is not None and model.literal_is_secret(a, string_value(b.attrs[a].raw)))]
        if nonliteral:
            fed, reason = model.federation_context("terraform", prov, "env", spec["static_type"])
            add(b, "terraform", ident(prov, f"{addr}.{spec['static_name']}"), prov, spec["static_type"], f"{addr}.{spec['static_name']}",
                "env", lifespan="long_lived", fed=(fed, reason), line=b.attrs[nonliteral[0]].line,
                locator=f"{addr}.{nonliteral[0]}")
        for blk_name in spec.get("federated_blocks", ()):
            for sub in b.blocks:
                if sub.type == blk_name:
                    role = string_value(sub.attrs["role_arn"].raw) if "role_arn" in sub.attrs else None
                    add(b, "terraform", ident(prov, f"{addr}.{blk_name}"), prov, "service_account", f"{addr}.{blk_name}",
                        "federated", lifespan="ephemeral", extra_res=[{"kind": "role", "value": role}] if role else [],
                        line=sub.line, locator=f"{addr}.{blk_name}")
        for attr, name, truthy in spec.get("federated_attrs", ()):
            if attr in b.attrs and (not truthy or b.attrs[attr].raw.strip() == "true"):
                val = string_value(b.attrs[attr].raw)
                add(b, "terraform", ident(prov, f"{addr}.{name}"), prov, "service_account", f"{addr}.{name}", "federated",
                    lifespan="ephemeral", extra_res=[{"kind": "role", "value": val}] if val and not truthy else [],
                    line=b.attrs[attr].line, locator=f"{addr}.{attr}")

    # literal secrets anywhere (provider keys, passwords, variable defaults) ---------
    def scan_literals(blk: Block, owner: Block, path: str):
        for an in sorted(blk.attrs):
            if an in POLICY_ATTRS:
                continue
            a = blk.attrs[an]
            v = string_value(a.raw)
            if v is None or not model.literal_is_secret(an, v):
                continue
            fmt = model.classify_literal(v)
            oaddr = owner.address() or owner.type
            pname = an
            if owner.type == "provider" and owner.labels and owner.labels[0] in PROVIDER_CREDENTIALS \
                    and an in PROVIDER_CREDENTIALS[owner.labels[0]]["static"]:
                pname = PROVIDER_CREDENTIALS[owner.labels[0]]["static_name"]
            prov = owner.labels[0] if owner.type == "provider" and owner.labels and owner.labels[0] in ("aws", "google", "azurerm") else None
            prov = {"google": "gcp", "azurerm": "azure"}.get(prov, prov) or model.infer_provider(an, [oaddr])
            if prov == "unknown":
                prov = model.FORMAT_PROVIDER.get(fmt["class"], "unknown")
            ctype = model.classify_type(an)
            if ctype == "unknown":
                ctype = model.FORMAT_TYPE.get(fmt["class"], "unknown")
            fed = model.federation_context("terraform", prov, "inline", ctype) if owner.type == "provider" else (False, None)
            add(owner, "terraform", ident(prov, f"{oaddr}.{path}{pname}"), prov, ctype, f"{oaddr}.{path}{pname}", "inline",
                fmt=fmt, fed=fed, line=a.line, locator=f"{oaddr}.{path}{an}")
        for sub in blk.blocks:
            scan_literals(sub, owner, f"{path}{sub.type}.")

    for b in blocks:
        if b.type in ("resource", "provider", "variable", "locals", "module", "data"):
            scan_literals(b, b, "")
    return out


def parse_terraform(rel_path: str, text: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    blocks, w1 = load_blocks(rel_path, text)
    entries, w2 = build(blocks)
    return entries, w1 + w2
