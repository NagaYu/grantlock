"""Identity model: deterministic classification tables and constructors.

Everything here is a pure function over *names* and *shapes*. Functions that
look at a literal value (``classify_literal``) return only a class name from a
closed table; they never return, store or hash the value itself.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from . import __version__

GENERATOR = {"name": "grantlock", "version": __version__}

# --------------------------------------------------------------------------
# Provider inference (code-resident data). Ordered: first match wins.
# Each row: (provider, name-token regex applied to the upper-cased name).
# --------------------------------------------------------------------------
PROVIDER_NAME_TABLE: list[tuple[str, str]] = [
    ("anthropic", r"(^|_)(ANTHROPIC|CLAUDE)(_|$)"),
    ("openai", r"(^|_)(OPENAI|OAI)(_|$)"),
    ("azure", r"(^|_)(AZURE|ARM|AZ)(_|$)"),
    ("aws", r"(^|_)(AWS|AMAZON|BEDROCK|S3)(_|$)"),
    ("gcp", r"(^|_)(GCP|GCLOUD|GOOGLE|GEMINI|VERTEX|FIREBASE|GCS)(_|$)"),
    ("github", r"(^|_)(GITHUB|GH|GHCR)(_|$)"),
    ("gitlab", r"(^|_)(GITLAB|GL)(_|$)"),
    ("slack", r"(^|_)SLACK(_|$)"),
    ("stripe", r"(^|_)STRIPE(_|$)"),
    ("notion", r"(^|_)NOTION(_|$)"),
    ("linear", r"(^|_)LINEAR(_|$)"),
    ("sentry", r"(^|_)SENTRY(_|$)"),
    ("datadog", r"(^|_)(DATADOG|DD)(_|$)"),
    ("atlassian", r"(^|_)(JIRA|ATLASSIAN|CONFLUENCE)(_|$)"),
    ("supabase", r"(^|_)SUPABASE(_|$)"),
    ("postgres", r"(^|_)(POSTGRES|POSTGRESQL|PG|DATABASE|DB)(_|$)"),
    ("mongodb", r"(^|_)(MONGO|MONGODB)(_|$)"),
    ("redis", r"(^|_)REDIS(_|$)"),
    ("snowflake", r"(^|_)SNOWFLAKE(_|$)"),
    ("npm", r"(^|_)(NPM|NODE_AUTH)(_|$)"),
    ("pypi", r"(^|_)(PYPI|TWINE)(_|$)"),
    ("docker", r"(^|_)(DOCKER|DOCKERHUB)(_|$)"),
    ("vercel", r"(^|_)VERCEL(_|$)"),
    ("cloudflare", r"(^|_)(CLOUDFLARE|CF)(_|$)"),
    ("huggingface", r"(^|_)(HUGGINGFACE|HF)(_|$)"),
    ("pinecone", r"(^|_)PINECONE(_|$)"),
    ("brave", r"(^|_)BRAVE(_|$)"),
    ("tavily", r"(^|_)TAVILY(_|$)"),
    ("perplexity", r"(^|_)(PERPLEXITY|PPLX)(_|$)"),
    ("twilio", r"(^|_)TWILIO(_|$)"),
    ("sendgrid", r"(^|_)SENDGRID(_|$)"),
    ("figma", r"(^|_)FIGMA(_|$)"),
    ("zendesk", r"(^|_)ZENDESK(_|$)"),
    ("hubspot", r"(^|_)HUBSPOT(_|$)"),
    ("codecov", r"(^|_)CODECOV(_|$)"),
    ("sonar", r"(^|_)(SONAR|SONARQUBE)(_|$)"),
]
_PROVIDER_NAME_RE = [(p, re.compile(rx)) for p, rx in PROVIDER_NAME_TABLE]

# Context hints: substrings of package names, images, hosts, actions.
PROVIDER_CONTEXT_TABLE: list[tuple[str, str]] = [
    ("github", "github"),
    ("anthropic", "anthropic"),
    ("openai", "openai"),
    ("slack", "slack"),
    ("notion", "notion"),
    ("linear", "linear"),
    ("sentry", "sentry"),
    ("stripe", "stripe"),
    ("atlassian", "atlassian"),
    ("supabase", "supabase"),
    ("postgres", "postgres"),
    ("mongodb", "mongo"),
    ("redis", "redis"),
    ("snowflake", "snowflake"),
    ("brave", "brave"),
    ("tavily", "tavily"),
    ("pinecone", "pinecone"),
    ("datadog", "datadog"),
    ("cloudflare", "cloudflare"),
    ("vercel", "vercel"),
    ("figma", "figma"),
    ("zendesk", "zendesk"),
    ("aws", "aws"),
    ("aws", "amazonaws"),
    ("gcp", "google"),
    ("gcp", "googleapis"),
    ("azure", "azure"),
    ("huggingface", "huggingface"),
    ("pypi", "pypi"),
    ("npm", "npmjs"),
    ("docker", "docker"),
]


def norm_name(name: str) -> str:
    """Upper snake case; splits camelCase (clientSecret -> CLIENT_SECRET)."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    return re.sub(r"[^A-Z0-9]+", "_", s.upper()).strip("_")


def infer_provider(name: str, context: Iterable[str] = ()) -> str:
    """Deterministic provider inference from a credential name, then context."""
    upper = norm_name(name)
    for provider, rx in _PROVIDER_NAME_RE:
        if rx.search(upper):
            return provider
    for ctx in context:
        low = (ctx or "").lower()
        for provider, needle in PROVIDER_CONTEXT_TABLE:
            if needle in low:
                return provider
        for provider, _ in PROVIDER_NAME_TABLE:
            if provider in low:
                return provider
    return "unknown"


# --------------------------------------------------------------------------
# Credential-name detection and type classification.
# --------------------------------------------------------------------------
_KEY_QUALIFIERS = {
    "API", "ACCESS", "SECRET", "PRIVATE", "SERVICE", "MASTER", "SIGNING", "ENCRYPTION",
    "LICENSE", "ADMIN", "SA", "ACCOUNT", "SUBSCRIPTION", "AUTH", "APP", "DEPLOY", "SSH",
    "WRITE", "READ", "INGEST", "MANAGEMENT", "PROJECT", "USER", "ORG",
}
_CRED_LAST = {
    "APIKEY", "TOKEN", "SECRET", "PASSWORD", "PASSWD", "PWD", "PAT", "CREDENTIALS",
    "CREDENTIAL", "DSN", "AUTHORIZATION", "COOKIE", "PASSPHRASE",
}
_NON_SECRET_KEY_PREFIX = {"PUBLIC", "PUBLISHABLE", "SITE", "PARTITION", "SORT", "CACHE", "IDEMPOTENCY", "PRIMARY", "FOREIGN"}
_DB_URL_NAMES = re.compile(
    r"^(DATABASE_URL|DB_URL|.*_DATABASE_URL|.*_DB_URL|REDIS_URL|.*_REDIS_URL|MONGODB_URI|MONGO_URI|"
    r".*_MONGODB_URI|POSTGRES_URL|.*_POSTGRES_URL|.*_CONNECTION_STRING|CONNECTION_STRING|.*_DSN_URL)$"
)
_WEBHOOK = re.compile(r"(^|_)WEBHOOK(_URL)?$")
_CRED_FILE = re.compile(r"^(GOOGLE_APPLICATION_CREDENTIALS|.*_KEY_FILE|.*_KEY_PATH|.*_CREDENTIALS_FILE|.*_CREDENTIALS_PATH)$")
# Names that are scope / configuration declarations, never secrets.
_SCOPE_NAME = re.compile(r"(^|_)(SCOPES|SCOPE|ROLE|TOOLSETS|PERMISSIONS)$")


def _tokens(name: str) -> list[str]:
    return [t for t in re.split(r"[^A-Z0-9]+", name.upper()) if t]


def is_scope_name(name: str) -> bool:
    return bool(_SCOPE_NAME.search(norm_name(name)))


def is_credential_name(name: str) -> bool:
    """True when a variable / key name denotes a credential (name-only rule)."""
    norm = norm_name(name)
    if not norm or is_scope_name(norm):
        return False
    if norm == "AWS_ACCESS_KEY_ID" or norm.endswith("_ACCESS_KEY_ID"):
        return True
    if _DB_URL_NAMES.match(norm) or _WEBHOOK.search(norm) or _CRED_FILE.match(norm):
        return True
    toks = _tokens(norm)
    last = toks[-1]
    if last in _CRED_LAST:
        if len(toks) >= 2 and toks[-2] in _NON_SECRET_KEY_PREFIX:
            return False
        return True
    if last == "KEY":
        if len(toks) == 1:
            return False
        prev = toks[-2]
        if prev in _NON_SECRET_KEY_PREFIX:
            return False
        if prev in _KEY_QUALIFIERS:
            return True
        # <PROVIDER>_KEY, e.g. OPENAI_KEY
        return infer_provider(norm) != "unknown"
    if norm in {"AUTHORIZATION", "X_API_KEY", "API_KEY", "APIKEY"}:
        return True
    return False


def classify_type(name: str) -> str:
    """Credential type from the name pattern (deterministic)."""
    n = norm_name(name)
    if "CLIENT_SECRET" in n or "OAUTH" in n or "REFRESH_TOKEN" in n or n.endswith("CLIENT_ID"):
        return "oauth"
    if (
        "SERVICE_ACCOUNT" in n
        or n.endswith("_SA_KEY")
        or "CREDENTIALS_JSON" in n
        or _CRED_FILE.match(n)
        or n.endswith("PRIVATE_KEY")
        or n in {"AZURE_CREDENTIALS", "GCP_CREDENTIALS", "GOOGLE_CREDENTIALS"}
        or n.endswith("_CREDENTIALS")
        or n.endswith("_CREDENTIAL")
    ):
        return "service_account"
    if _DB_URL_NAMES.match(n) or n.endswith(("PASSWORD", "PASSWD", "_PWD", "PASSPHRASE")):
        return "password"
    if n.endswith(("_KEY", "APIKEY", "_KEY_ID")) or n in {"API_KEY", "X_API_KEY"}:
        return "api_key"
    if n.endswith(("TOKEN", "_PAT", "_DSN", "COOKIE", "AUTHORIZATION")) or _WEBHOOK.search(n):
        return "token"
    return "unknown"


# Aliases: two halves of one static key pair are one identity.
CREDENTIAL_ALIASES = {"AWS_SECRET_ACCESS_KEY": "AWS_ACCESS_KEY_ID"}


def canonical_name(name: str) -> str:
    return CREDENTIAL_ALIASES.get(name, name)


def identity_id(provider: str, name: str) -> str:
    return f"{provider}:{canonical_name(name)}"


# --------------------------------------------------------------------------
# Literal value handling. Values are inspected transiently and discarded.
# --------------------------------------------------------------------------
_REF_PATTERNS = [
    re.compile(r"^\$\{(env:)?[A-Za-z_][A-Za-z0-9_]*\}$"),
    re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$"),
    re.compile(r"^\$\{input:[A-Za-z0-9_.-]+\}$"),
    re.compile(r"^\$\{\{\s*[^}]+\}\}$"),  # GitHub Actions expression
    re.compile(r"^\{\{\s*[^}]+\}\}$"),  # templating
    re.compile(r"^%[A-Za-z_][A-Za-z0-9_]*%$"),
]
_EMBEDDED_REF = re.compile(r"\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}|\$\{input:([A-Za-z0-9_.-]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
_PLACEHOLDER = re.compile(
    r"^(<[^>]*>|\[[^\]]*\]|x{3,}|\*{3,}|\.{3,}|todo|tbd|changeme|change[-_ ]?me|replace[-_ ]?me|"
    r"your[-_ ].*|your_.*|.*[-_]here|insert[-_ ].*|placeholder|none|null|redacted|dummy|example|"
    r"sk-\.\.\.|sk-x+|<redacted>)$",
    re.IGNORECASE,
)


def is_reference(value: str) -> bool:
    v = value.strip()
    return any(p.match(v) for p in _REF_PATTERNS)


def referenced_names(value: str) -> list[str]:
    """Variable names referenced inside a string such as 'Bearer ${TOKEN}'."""
    out = []
    for m in _EMBEDDED_REF.finditer(value):
        name = m.group(1) or m.group(2) or m.group(3)
        if name and name not in out:
            out.append(name)
    return out


def is_placeholder(value: str) -> bool:
    v = value.strip()
    return v == "" or bool(_PLACEHOLDER.match(v))


def is_non_secret_literal(value: str) -> bool:
    """Booleans, numbers, paths and plain URLs without credentials are configuration."""
    v = value.strip()
    if v.lower() in {"true", "false", "yes", "no", "on", "off", "0", "1"}:
        return True
    if re.fullmatch(r"-?\d+(\.\d+)?", v):
        return True
    if re.fullmatch(r"(~|\.{1,2})?/[\w./~-]*", v) or re.fullmatch(r"[A-Za-z]:\\[\w\\. -]*", v):
        return True
    if re.match(r"^[a-z][a-z0-9+.-]*://", v) and not url_has_password(v):
        return True
    return False


_URL_USERINFO = re.compile(r"^[a-z][a-z0-9+.-]*://([^/@\s]*)@", re.IGNORECASE)


def url_has_password(value: str) -> bool:
    m = _URL_USERINFO.match(value.strip())
    if not m:
        return False
    userinfo = m.group(1)
    if ":" not in userinfo:
        return False
    pw = userinfo.split(":", 1)[1]
    return pw != "" and not is_reference(pw) and not referenced_names(pw)


def url_host(value: str) -> str | None:
    """Host name of a URL with userinfo stripped (never returns credentials)."""
    m = re.match(r"^[a-z][a-z0-9+.-]*://(?:[^/@\s]*@)?(\[[^\]]+\]|[^/:?#\s]+)", value.strip(), re.IGNORECASE)
    if not m:
        return None
    host = m.group(1).lower()
    if "$" in host or "{" in host:
        return None
    return host


# Format table: (class, prefix-as-recorded, regex). The recorded prefix is the
# literal string in this table, never a slice of the inspected value.
FORMAT_TABLE: list[tuple[str, str | None, re.Pattern[str]]] = [
    ("private_key_pem", "-----BEGIN", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("anthropic_key", "sk-ant-", re.compile(r"^sk-ant-[A-Za-z0-9_-]{8,}$")),
    ("stripe_secret_key", "sk_live_", re.compile(r"^sk_live_[A-Za-z0-9]{8,}$")),
    ("stripe_secret_key", "sk_test_", re.compile(r"^sk_test_[A-Za-z0-9]{8,}$")),
    ("openai_key", "sk-", re.compile(r"^sk-(proj-)?[A-Za-z0-9_-]{8,}$")),
    ("github_pat_fine_grained", "github_pat_", re.compile(r"^github_pat_[A-Za-z0-9_]{8,}$")),
    ("github_pat_classic", "ghp_", re.compile(r"^ghp_[A-Za-z0-9]{8,}$")),
    ("github_oauth_token", "gho_", re.compile(r"^gho_[A-Za-z0-9]{8,}$")),
    ("github_app_token", "ghs_", re.compile(r"^gh[su]_[A-Za-z0-9]{8,}$")),
    ("gitlab_pat", "glpat-", re.compile(r"^glpat-[A-Za-z0-9_-]{8,}$")),
    ("aws_access_key_id", "AKIA", re.compile(r"^(AKIA|ASIA)[A-Z0-9]{16}$")),
    # recorded descriptor is the host only, to stay within the schema's 16-character prefix limit (D-050)
    ("slack_webhook_url", "hooks.slack.com", re.compile(r"^https://hooks\.slack\.com/services/")),
    ("slack_token", "xox", re.compile(r"^xox[abposr]-[A-Za-z0-9-]{8,}$")),
    ("google_api_key", "AIza", re.compile(r"^AIza[0-9A-Za-z_-]{20,}$")),
    ("npm_token", "npm_", re.compile(r"^npm_[A-Za-z0-9]{36}$")),  # real format: npm_ + 36 (D-036)
    ("pypi_token", "pypi-", re.compile(r"^pypi-[A-Za-z0-9_-]{8,}$")),
    ("huggingface_token", "hf_", re.compile(r"^hf_[A-Za-z0-9]{8,}$")),
    ("sendgrid_key", "SG.", re.compile(r"^SG\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")),
    ("jwt", "eyJ", re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")),
]

FORMAT_PROVIDER = {
    "anthropic_key": "anthropic",
    "openai_key": "openai",
    "github_pat_classic": "github",
    "github_pat_fine_grained": "github",
    "github_oauth_token": "github",
    "github_app_token": "github",
    "gitlab_pat": "gitlab",
    "aws_access_key_id": "aws",
    "slack_token": "slack",
    "slack_webhook_url": "slack",
    "stripe_secret_key": "stripe",
    "google_api_key": "gcp",
    "npm_token": "npm",
    "pypi_token": "pypi",
    "huggingface_token": "huggingface",
    "sendgrid_key": "sendgrid",
}


def classify_known_shape(value: str) -> dict[str, Any] | None:
    """Return {'class', 'prefix'} when the literal matches a known secret shape."""
    v = value.strip()
    if v.lower().startswith(("bearer ", "token ")):
        inner = v.split(None, 1)[1] if len(v.split(None, 1)) == 2 else ""
        inner_fmt = classify_known_shape(inner)
        return inner_fmt or {"class": "bearer_literal", "prefix": None}
    if v.lower().startswith("basic "):
        return {"class": "basic_auth_literal", "prefix": None}
    if url_has_password(v):
        return {"class": "connection_string_with_password", "prefix": None}
    for cls, prefix, rx in FORMAT_TABLE:
        if rx.search(v):
            return {"class": cls, "prefix": prefix}
    return None


def classify_literal(value: str) -> dict[str, Any]:
    """Format class of a literal judged to be a secret (never the value)."""
    return classify_known_shape(value) or {"class": "generic_literal", "prefix": None}


def literal_is_secret(name: str | None, value: Any) -> bool:
    """Decide whether a literal (non-reference) value is an inline secret.

    A secret-shaped literal is inline regardless of the key name; a
    credential-named key holding any non-placeholder, non-config literal is inline.
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if is_placeholder(v) or is_reference(v):
        return False
    if referenced_names(v) and not url_has_password(v):
        # e.g. "Bearer ${TOKEN}" or "postgres://u:${PW}@h/db": a reference, not a literal.
        return False
    if classify_known_shape(v) is not None:
        return True
    if name is not None and is_credential_name(name):
        return not is_non_secret_literal(v)
    return False


# --------------------------------------------------------------------------
# Wildcard / admin-level detection (G3 material). Deterministic list.
# --------------------------------------------------------------------------
ADMIN_SEGMENTS = {
    "admin", "administrator", "administratoraccess", "administration", "owner", "owners",
    "root", "superuser", "superadmin", "full_access", "fullaccess", "poweruseraccess",
}


# Exact role names that are admin-level although no segment says "admin"/"owner" (Phase 2).
ADMIN_ROLES_EXACT = {"roles/editor", "contributor", "user access administrator", "roles/iam.securityadmin"}
_RBAC_SECRETS_WIDE = re.compile(r"^rbac:cluster:(get|list|watch):secrets$")
_RBAC_ESCALATION_VERBS = {"impersonate", "escalate", "bind"}


def wildcard_reasons(scopes: Iterable[str], scope_source: str = "unknown") -> list[str]:
    reasons: list[str] = []
    if scope_source == "write-all":
        reasons.append("permissions: write-all")
    for s in scopes:
        low = s.lower()
        if low.startswith("iam:resource:"):
            # an ARN such as arn:aws:s3:::bucket/* is object-level, not a wildcard grant
            if low == "iam:resource:*":
                reasons.append("IAM Resource '*'")
            continue
        if low.startswith("role:") and low[5:] in ADMIN_ROLES_EXACT:
            reasons.append(f"admin-level role '{s[5:]}'")
            continue
        if _RBAC_SECRETS_WIDE.match(low):
            reasons.append(f"cluster-wide access to secrets '{s}'")
            continue
        if low.startswith("rbac:") and low.split(":")[2:3] and low.split(":")[2] in _RBAC_ESCALATION_VERBS:
            reasons.append(f"privilege-escalation verb '{s}'")
            continue
        if "*" in low:
            reasons.append(f"wildcard scope '{s}'")
            continue
        segs = [x for x in re.split(r"[:/.,\s=]+", low) if x]
        # GitHub levels (read/write) are not role names.
        for seg in segs:
            if seg in ADMIN_SEGMENTS or (seg.endswith("admin") and len(seg) > 5):
                reasons.append(f"admin-level scope '{s}'")
                break
    return reasons


def lifespan_for(storage: str, ctype: str) -> str:
    if storage == "federated":
        return "ephemeral"
    if ctype == "oauth" and storage == "vault_ref":
        return "rotating"
    if ctype == "unknown":
        return "unknown"
    return "long_lived"


def make_component(kind: str, name: str, file: str, local_id: str | None = None) -> dict[str, str]:
    cid = f"{kind}:{file}#{local_id if local_id is not None else name}"
    return {"id": cid, "kind": kind, "name": name, "file": file}


def make_entry(
    *,
    identity: str,
    component: dict[str, str],
    provider: str,
    ctype: str,
    name: str,
    storage: str,
    fmt: dict[str, Any] | None = None,
    scopes: Iterable[str] = (),
    scopes_known: bool = False,
    scope_source: str = "unknown",
    resources: Iterable[dict[str, str]] = (),
    lifespan: str | None = None,
    federation_available: bool = False,
    federation_reason: str | None = None,
    evidence: Iterable[dict[str, Any]] = (),
) -> dict[str, Any]:
    if storage != "inline":
        fmt = None
    return {
        "identity_id": identity,
        "component": dict(component),
        "credential": {
            "provider": provider,
            "type": ctype,
            "name": canonical_name(name),
            "storage": storage,
            "format": fmt,
        },
        "scopes": sorted(set(scopes)),
        "scopes_known": bool(scopes_known),
        "scope_source": scope_source,
        "resources": sort_resources(resources),
        "owner": None,
        "lifespan": lifespan or lifespan_for(storage, ctype),
        "context": {"federation_available": federation_available, "reason": federation_reason},
        "evidence": sorted(
            (dict(e) for e in evidence),
            key=lambda e: (e["file"], e["line"] if e["line"] is not None else -1, e["locator"]),
        ),
    }


def sort_resources(resources: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    uniq = {(r["kind"], r["value"]) for r in resources}
    return [{"kind": k, "value": v} for k, v in sorted(uniq)]


# --------------------------------------------------------------------------
# Federation / short-lived alternatives (G6 material). Deterministic table:
# (component kind, provider) -> why a long-lived static key is avoidable there.
# --------------------------------------------------------------------------
FEDERATION_TABLE: dict[tuple[str, str], str] = {
    ("gha_workflow", "aws"): "GitHub Actions OIDC -> AWS IAM role (aws-actions/configure-aws-credentials role-to-assume)",
    ("gha_workflow", "gcp"): "GitHub Actions OIDC -> GCP Workload Identity Federation (google-github-actions/auth)",
    ("gha_workflow", "azure"): "GitHub Actions OIDC -> Azure federated credential (azure/login client-id/tenant-id)",
    ("gha_workflow", "pypi"): "GitHub Actions OIDC -> PyPI Trusted Publishing",
    ("gha_workflow", "npm"): "GitHub Actions OIDC -> npm Trusted Publishing",
    ("mcp_server", "aws"): "short-lived alternative: AWS IAM Identity Center (SSO) profile via AWS_PROFILE",
    ("mcp_server", "gcp"): "short-lived alternative: gcloud ADC / service-account impersonation",
    ("mcp_server", "azure"): "short-lived alternative: az login / managed identity (DefaultAzureCredential)",
    ("compose_service", "aws"): "short-lived alternative: mount an AWS SSO profile / use the host instance role instead of static keys",
    ("compose_service", "gcp"): "short-lived alternative: mount gcloud ADC / impersonation instead of a key file",
    ("compose_service", "azure"): "short-lived alternative: az login / managed identity instead of a client secret",
    ("k8s_workload", "aws"): "Kubernetes federation: IRSA / EKS Pod Identity (eks.amazonaws.com/role-arn)",
    ("k8s_workload", "gcp"): "Kubernetes federation: GKE Workload Identity (iam.gke.io/gcp-service-account)",
    ("k8s_workload", "azure"): "Kubernetes federation: Azure Workload Identity",
    ("terraform", "aws"): "AWS supports federation (IAM OIDC/SAML providers, IAM Identity Center) instead of IAM user access keys",
    ("terraform", "gcp"): "GCP supports Workload Identity Federation / impersonation instead of service-account keys",
    ("terraform", "azure"): "Azure supports federated credentials / managed identities instead of client secrets",
    ("k8s_secret", "kubernetes"): "use projected (bound, short-lived) service-account tokens instead of a legacy token Secret",
}

STATIC_KEY_TYPES = {"api_key", "service_account", "token", "oauth", "password"}


def federation_context(component_kind: str, provider: str, storage: str, ctype: str) -> tuple[bool, str | None]:
    if storage == "federated" or ctype not in STATIC_KEY_TYPES:
        return False, None
    reason = FEDERATION_TABLE.get((component_kind, provider))
    return (reason is not None), reason


FORMAT_TYPE = {
    "anthropic_key": "api_key",
    "openai_key": "api_key",
    "aws_access_key_id": "api_key",
    "google_api_key": "api_key",
    "stripe_secret_key": "api_key",
    "sendgrid_key": "api_key",
    "github_pat_classic": "token",
    "github_pat_fine_grained": "token",
    "github_oauth_token": "oauth",
    "github_app_token": "token",
    "gitlab_pat": "token",
    "slack_token": "token",
    "slack_webhook_url": "token",
    "npm_token": "token",
    "pypi_token": "token",
    "huggingface_token": "token",
    "jwt": "token",
    "bearer_literal": "token",
    "basic_auth_literal": "password",
    "connection_string_with_password": "password",
    "private_key_pem": "service_account",
}


# --------------------------------------------------------------------------
# GitHub Actions permission normalization.
# --------------------------------------------------------------------------
GHA_SCOPES = [
    "actions", "checks", "contents", "deployments", "discussions", "id-token", "issues",
    "packages", "pages", "pull-requests", "repository-projects", "security-events", "statuses",
]
GHA_LEVELS = {"none": 0, "read": 1, "write": 2}


def expand_scopes(scopes: Iterable[str]) -> set[str]:
    """Comparison form: '<scope>:write' implies '<scope>:read'."""
    out: set[str] = set()
    for s in scopes:
        out.add(s)
        if s.endswith(":write"):
            out.add(s[: -len(":write")] + ":read")
    return out
