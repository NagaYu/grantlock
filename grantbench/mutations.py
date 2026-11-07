"""Risk mutations for GrantBench. Each planted variant edits a spec in place and
returns the planted list; each diff-pair variant also declares its expected
labels. Labels are derived from SPEC.md semantics by hand, never by running
GrantLock.
"""

from __future__ import annotations

import random
from typing import Any, Callable

from .templates import CATALOG, CRED_SERVERS, REMOTE_OAUTH, fake_secret, gha_component, ref_for

Planted = list[dict[str, str]]

EXTRA_REMOTES = {
    "linear": "https://mcp.linear.app/mcp",
    "sentry": "https://mcp.sentry.dev/mcp",
    "atlassian": "https://mcp.atlassian.com/v1/sse",
    "asana": "https://mcp.asana.com/sse",
    "intercom": "https://mcp.intercom.com/sse",
}


class Sink:
    """Collects the fake secret values a mutation planted (kept in memory only)."""

    def __init__(self) -> None:
        self.values: list[str] = []

    def fake(self, rng: random.Random, kind: str) -> str:
        v = fake_secret(rng, kind)
        self.values.append(v)
        return v


def _p(cls: str, file: str, component: str, note: str) -> dict[str, str]:
    return {"class": cls, "file": file, "component": component, "note": note}


def requires(*req: str) -> Callable:
    def deco(fn):
        fn.requires = set(req)
        return fn
    return deco


def _wf_path(f: str) -> str:
    return f".github/workflows/{f}"


def _deploy_file(spec) -> str:
    return "deploy.yml" if "deploy.yml" in spec["workflows"] else "release.yml"


def _deploy_job(spec) -> tuple[str, str]:
    f = _deploy_file(spec)
    job = next(iter(spec["workflows"][f]["jobs"]))
    return f, job


def _cred_server(spec, rng) -> tuple[str, str]:
    """(server, env key) of a server holding an env credential reference."""
    cands = []
    for name in sorted(spec["servers"]):
        s = spec["servers"][name]
        for k in sorted(s.get("env", {}) or {}):
            if name in CRED_SERVERS | {"github"} and k.endswith(("TOKEN", "KEY", "PASSWORD")) and "${" in str(s["env"][k]):
                cands.append((name, k))
    return rng.choice(cands)


def _step_env(step: dict, name: str, value: str) -> None:
    step.setdefault("env", {})[name] = value


def _add_server(spec, name, server, declare: list[str] | None = None) -> None:
    if spec["dialect"] == "vscode" and "command" in server:
        server = dict({"type": "stdio"}, **server)
    spec["servers"][name] = server
    if declare:
        spec["env_example"][0][1].extend(declare)


def _new_remote(spec, rng) -> str:
    free = [n for n in sorted(EXTRA_REMOTES) if n not in spec["servers"]]
    return rng.choice(free)


_PROVIDER_KIND = {"GITHUB_PERSONAL_ACCESS_TOKEN": "github", "SLACK_BOT_TOKEN": "slack"}

# ============================================================================ G1


@requires("cred_server")
def g1_env_literal(spec, rng, sink):
    srv, key = _cred_server(spec, rng)
    spec["servers"][srv]["env"][key] = sink.fake(rng, _PROVIDER_KIND.get(key, "generic"))
    return [_p("G1", spec["mcp_path"], srv, f"literal value pasted into env.{key}")]


@requires("server:postgres")
def g1_conn_string(spec, rng, sink):
    args = spec["servers"]["postgres"]["args"]
    pw = sink.fake(rng, "password")
    args[-1] = args[-1].replace(ref_for(spec, "PG_READONLY_PASSWORD"), pw)
    return [_p("G1", spec["mcp_path"], "postgres", "password embedded in connection string argument")]


def g1_header_literal(spec, rng, sink):
    _add_server(spec, "github-remote", {"type": "http", "url": "https://api.githubcopilot.com/mcp/",
                                        "headers": {"Authorization": "Bearer " + sink.fake(rng, "github")}})
    return [_p("G1", spec["mcp_path"], "github-remote", "PAT pasted into Authorization header")]


@requires("eval")
def g1_workflow_env(spec, rng, sink):
    steps = spec["workflows"]["eval.yml"]["jobs"]["eval"]["steps"]
    steps[-1]["env"]["ANTHROPIC_API_KEY"] = sink.fake(rng, "anthropic")
    return [_p("G1", _wf_path("eval.yml"), gha_component(spec, "eval.yml", "eval"), "API key hard-coded in step env")]


def g1_run_token(spec, rng, sink):
    steps = spec["workflows"]["ci.yml"]["jobs"]["test"]["steps"]
    tok = sink.fake(rng, "slack")
    steps.append({"name": "notify", "if": "${{ failure() }}",
                  "run": f'curl -sS -X POST -H "Authorization: Bearer {tok}" \\\n  -d "channel=C0ALERTS&text=CI failed" https://slack.com/api/chat.postMessage\n'})
    return [_p("G1", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "test"), "bot token in run script")]


def g1_args_key(spec, rng, sink):
    _add_server(spec, "openai-bridge", {"command": "uvx", "args": ["openai-mcp-bridge", "--api-key", sink.fake(rng, "openai")]})
    return [_p("G1", spec["mcp_path"], "openai-bridge", "API key passed as CLI argument")]


@requires("docker")
def g1_with_literal(spec, rng, sink):
    steps = spec["workflows"]["docker.yml"]["jobs"]["image"]["steps"]
    for st in steps:
        if str(st.get("uses", "")).startswith("docker/login-action"):
            st["with"]["password"] = sink.fake(rng, "github")
    return [_p("G1", _wf_path("docker.yml"), gha_component(spec, "docker.yml", "image"), "registry PAT as literal action input")]


# ============================================================================ G2


def g2_job_pr_write(spec, rng, sink):
    spec["workflows"]["ci.yml"]["jobs"]["test"]["permissions"] = {"contents": "read", "pull-requests": "write"}
    return [_p("G2", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "test"), "pull-requests: write added to test job")]


@requires("deploy")
def g2_deploy_add(spec, rng, sink):
    f, job = _deploy_job(spec)
    spec["workflows"][f]["jobs"][job]["permissions"]["deployments"] = "write"
    return [_p("G2", _wf_path(f), gha_component(spec, f, job), "deployments: write added to production job")]


def g2_remove_workflow_perms(spec, rng, sink):
    del spec["workflows"]["ci.yml"]["permissions"]
    return [_p("G2", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "test"), "workflow permissions removed -> implicit default")]


def g2_toolsets(spec, rng, sink):
    spec["servers"]["github"]["env"]["GITHUB_TOOLSETS"] = "repos,issues,pull_requests,actions"
    return [_p("G2", spec["mcp_path"], "github", "toolsets pull_requests,actions added")]


def g2_ci_contents_write(spec, rng, sink):
    spec["workflows"]["ci.yml"]["permissions"] = {"contents": "write"}
    return [_p("G2", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "test"), "workflow contents: read -> write")]


@requires("eval")
def g2_eval_issues(spec, rng, sink):
    spec["workflows"]["eval.yml"]["jobs"]["eval"]["permissions"] = {"contents": "read", "issues": "write"}
    return [_p("G2", _wf_path("eval.yml"), gha_component(spec, "eval.yml", "eval"), "issues: write added to eval job")]


@requires("docker")
def g2_docker_attest(spec, rng, sink):
    perms = spec["workflows"]["docker.yml"]["jobs"]["image"]["permissions"]
    perms["id-token"] = "write"
    perms["attestations"] = "write"
    return [_p("G2", _wf_path("docker.yml"), gha_component(spec, "docker.yml", "image"), "id-token/attestations write added")]


def g2_lint_checks_write(spec, rng, sink):
    spec["workflows"]["ci.yml"]["jobs"]["lint"]["permissions"] = {"contents": "read", "checks": "write"}
    return [_p("G2", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "lint"), "checks: write added to lint job")]


# ============================================================================ G3


def g3_job_write_all(spec, rng, sink):
    spec["workflows"]["ci.yml"]["jobs"]["test"]["permissions"] = "write-all"
    return [_p("G3", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "test"), "permissions: write-all on job")]


@requires("deploy_aws")
def g3_admin_role(spec, rng, sink):
    st = next(s for s in spec["workflows"]["deploy.yml"]["jobs"]["deploy"]["steps"] if "aws-actions" in str(s.get("uses", "")))
    st["with"]["role-to-assume"] = st["with"]["role-to-assume"].rsplit("/", 1)[0] + "/AdministratorAccess"
    return [_p("G3", _wf_path("deploy.yml"), gha_component(spec, "deploy.yml", "deploy"), "OIDC role switched to AdministratorAccess")]


def g3_toolsets_all(spec, rng, sink):
    spec["servers"]["github"]["env"]["GITHUB_TOOLSETS"] = "all"
    return [_p("G3", spec["mcp_path"], "github", "GITHUB_TOOLSETS=all")]


def g3_wf_write_all(spec, rng, sink):
    spec["workflows"]["ci.yml"]["permissions"] = "write-all"
    spec["workflows"]["ci.yml"]["jobs"]["test"].pop("permissions", None)
    return [_p("G3", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "test"), "workflow-level write-all")]


def g3_snowflake_admin(spec, rng, sink):
    _add_server(spec, "snowflake", {"command": "uvx", "args": ["snowflake-labs-mcp", "--service-config-file", "config/snowflake.yaml"],
                                    "env": {"SNOWFLAKE_ACCOUNT": f"{spec['ctx']['org']}-analytics", "SNOWFLAKE_USER": "AGENT_SVC",
                                            "SNOWFLAKE_ROLE": "ACCOUNTADMIN", "SNOWFLAKE_PASSWORD": ref_for(spec, "SNOWFLAKE_PASSWORD")}},
                ["SNOWFLAKE_PASSWORD"])
    return [_p("G3", spec["mcp_path"], "snowflake", "agent runs as ACCOUNTADMIN")]


@requires("deploy_gcp")
def g3_gcp_admin_sa(spec, rng, sink):
    st = next(s for s in spec["workflows"]["deploy.yml"]["jobs"]["deploy"]["steps"] if "google-github-actions" in str(s.get("uses", "")))
    st["with"]["service_account"] = f"gha-admin@{spec['ctx']['gcp_project']}.iam.gserviceaccount.com"
    return [_p("G3", _wf_path("deploy.yml"), gha_component(spec, "deploy.yml", "deploy"), "deploys as an admin service account")]


# ============================================================================ G4


def _mcp_rule(spec) -> str:
    return {"claude": "/.mcp.json", "cursor": "/.cursor/", "vscode": "/.vscode/"}[spec["dialect"]]


def g4_drop_mcp_rule(spec, rng, sink):
    rule = _mcp_rule(spec)
    spec["codeowners"] = [r for r in spec["codeowners"] if r[0] != rule]
    return [_p("G4", spec["mcp_path"], "github", "CODEOWNERS rule for MCP config removed")]


def g4_drop_github_rule(spec, rng, sink):
    spec["codeowners"] = [r for r in spec["codeowners"] if r[0] != "/.github/"]
    return [_p("G4", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "test"), "CODEOWNERS rule for .github removed")]


@requires("eval")
def g4_narrow_github_rule(spec, rng, sink):
    owners = next(o for p, o in spec["codeowners"] if p == "/.github/")
    spec["codeowners"] = [r for r in spec["codeowners"] if r[0] != "/.github/"] + [
        ("/.github/workflows/ci.yml", owners), ("/.github/CODEOWNERS", owners)]
    return [_p("G4", _wf_path("eval.yml"), gha_component(spec, "eval.yml", "eval"), "rule narrowed to ci.yml only")]


def g4_typo(spec, rng, sink):
    spec["codeowners"] = [("/.githb/", o) if p == "/.github/" else (p, o) for p, o in spec["codeowners"]]
    return [_p("G4", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "test"), "typo in CODEOWNERS path")]


def g4_delete_codeowners(spec, rng, sink):
    spec["codeowners"] = None
    return [_p("G4", spec["mcp_path"], "github", "CODEOWNERS deleted")]


def g4_explicit_unowned(spec, rng, sink):
    spec["codeowners"].append((_mcp_rule(spec), []))
    return [_p("G4", spec["mcp_path"], "github", "trailing rule without owners un-owns the MCP config")]


# ============================================================================ G5


def g5_second_server_same_pat(spec, rng, sink):
    _add_server(spec, "triage-bot", {"command": "npx", "args": ["-y", f"@{spec['ctx']['org']}/triage-mcp"],
                                     "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": ref_for(spec, "GITHUB_PERSONAL_ACCESS_TOKEN")}})
    return [_p("G5", spec["mcp_path"], "triage-bot", "reuses github PAT"), _p("G5", spec["mcp_path"], "github", "PAT now shared")]


@requires("eval")
def g5_eval_secret_in_ci(spec, rng, sink):
    steps = spec["workflows"]["ci.yml"]["jobs"]["test"]["steps"]
    steps.append({"name": "agent smoke test", "run": "python -m evals.run --suite smoke",
                  "env": {"ANTHROPIC_API_KEY": "${{ secrets.EVAL_ANTHROPIC_API_KEY }}"}})
    return [_p("G5", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "test"), "eval key reused in CI"),
            _p("G5", _wf_path("eval.yml"), gha_component(spec, "eval.yml", "eval"), "eval key now shared")]


@requires("cred_server")
def g5_second_mcp_file(spec, rng, sink):
    srv, _key = _cred_server(spec, rng)
    if spec["mcp_path"] == ".mcp.json":
        alt, dialect, root, rule = ".cursor/mcp.json", "cursor", "mcpServers", "/.cursor/"
    else:
        alt, dialect, root, rule = ".mcp.json", "claude", "mcpServers", "/.mcp.json"
    server = {k: v for k, v in spec["servers"][srv].items() if k != "type"}
    server = {k: (({ek: ev.replace("${env:", "${") for ek, ev in v.items()}) if k == "env" else v) for k, v in server.items()}
    spec["extra_mcp_files"][alt] = ({srv: server}, dialect, root)
    owners = next(o for p, o in spec["codeowners"] if p == _mcp_rule(spec))
    spec["codeowners"].append((rule, owners))
    return [_p("G5", alt, srv, "server copied into a second client config"), _p("G5", spec["mcp_path"], srv, "credential now shared")]


@requires("deploy_aws")
def g5_shared_role(spec, rng, sink):
    import copy as _c
    wf = _c.deepcopy(spec["workflows"]["deploy.yml"])
    wf["name"] = "Hotfix"
    wf["on"] = {"workflow_dispatch": None}
    wf.pop("concurrency", None)
    spec["workflows"]["hotfix.yml"] = wf
    spec["wf_comments"]["hotfix.yml"] = ["Manual hotfix deploy"]
    return [_p("G5", _wf_path("hotfix.yml"), "Hotfix/deploy", "same OIDC role as Deploy"),
            _p("G5", _wf_path("deploy.yml"), gha_component(spec, "deploy.yml", "deploy"), "role now shared")]


@requires("codecov")
def g5_codecov_two_jobs(spec, rng, sink):
    spec["workflows"]["ci.yml"]["jobs"]["lint"]["steps"].append(
        {"name": "upload lint report", "uses": "codecov/test-results-action@v1", "with": {"token": "${{ secrets.CODECOV_TOKEN }}"}})
    return [_p("G5", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "lint"), "codecov token reused in lint")]


@requires("server:slack")
def g5_slack_reuse(spec, rng, sink):
    _add_server(spec, "standup-bot", {"command": "npx", "args": ["-y", f"@{spec['ctx']['org']}/standup-mcp"],
                                      "env": {"SLACK_BOT_TOKEN": ref_for(spec, "SLACK_BOT_TOKEN")}})
    return [_p("G5", spec["mcp_path"], "standup-bot", "reuses slack bot token"), _p("G5", spec["mcp_path"], "slack", "token now shared")]


# ============================================================================ G6


@requires("deploy_aws")
def g6_aws_static_replace(spec, rng, sink):
    job = spec["workflows"]["deploy.yml"]["jobs"]["deploy"]
    st = next(s for s in job["steps"] if "aws-actions" in str(s.get("uses", "")))
    region = st["with"]["aws-region"]
    st["with"] = {"aws-access-key-id": "${{ secrets.AWS_ACCESS_KEY_ID }}",
                  "aws-secret-access-key": "${{ secrets.AWS_SECRET_ACCESS_KEY }}", "aws-region": region}
    job["permissions"].pop("id-token", None)
    return [_p("G6", _wf_path("deploy.yml"), gha_component(spec, "deploy.yml", "deploy"), "OIDC replaced by static keys")]


def g6_backup_job(spec, rng, sink):
    spec["workflows"]["backup.yml"] = {
        "name": "Backup", "on": {"schedule": [{"cron": "0 2 * * *"}]}, "permissions": {"contents": "read"},
        "jobs": {"backup": {"runs-on": "ubuntu-latest", "steps": [
            {"name": "sync", "run": f"aws s3 sync s3://{spec['ctx']['project']}-data s3://{spec['ctx']['project']}-backup",
             "env": {"AWS_ACCESS_KEY_ID": "${{ secrets.BACKUP_AWS_ACCESS_KEY_ID }}",
                     "AWS_SECRET_ACCESS_KEY": "${{ secrets.BACKUP_AWS_SECRET_ACCESS_KEY }}"}}]}}}
    return [_p("G6", _wf_path("backup.yml"), "Backup/backup", "static AWS keys in nightly job")]


@requires("deploy_gcp")
def g6_gcp_sa_key(spec, rng, sink):
    st = next(s for s in spec["workflows"]["deploy.yml"]["jobs"]["deploy"]["steps"] if "google-github-actions" in str(s.get("uses", "")))
    st["with"] = {"credentials_json": "${{ secrets.GCP_SA_KEY }}"}
    return [_p("G6", _wf_path("deploy.yml"), gha_component(spec, "deploy.yml", "deploy"), "WIF replaced by SA key JSON")]


@requires("deploy_azure")
def g6_azure_creds(spec, rng, sink):
    st = next(s for s in spec["workflows"]["deploy.yml"]["jobs"]["deploy"]["steps"] if "azure/login" in str(s.get("uses", "")))
    st["with"] = {"creds": "${{ secrets.AZURE_CREDENTIALS }}"}
    return [_p("G6", _wf_path("deploy.yml"), gha_component(spec, "deploy.yml", "deploy"), "federated login replaced by creds JSON")]


@requires("release_pypi")
def g6_pypi_token(spec, rng, sink):
    st = next(s for s in spec["workflows"]["release.yml"]["jobs"]["publish"]["steps"] if "pypi-publish" in str(s.get("uses", "")))
    st["with"] = {"password": "${{ secrets.PYPI_API_TOKEN }}"}
    return [_p("G6", _wf_path("release.yml"), gha_component(spec, "release.yml", "publish"), "trusted publishing replaced by API token")]


def g6_mcp_aws(spec, rng, sink):
    _add_server(spec, "aws", {"command": "uvx", "args": ["awslabs.aws-api-mcp-server@latest"],
                              "env": {"AWS_ACCESS_KEY_ID": ref_for(spec, "AWS_ACCESS_KEY_ID"),
                                      "AWS_SECRET_ACCESS_KEY": ref_for(spec, "AWS_SECRET_ACCESS_KEY"),
                                      "AWS_REGION": spec["ctx"]["region"]}},
                ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"])
    return [_p("G6", spec["mcp_path"], "aws", "static IAM user keys for agent")]


def g6_mcp_bigquery(spec, rng, sink):
    _add_server(spec, "bigquery", {"command": "uvx", "args": ["mcp-server-bigquery", "--project", spec["ctx"]["gcp_project"]],
                                   "env": {"GOOGLE_APPLICATION_CREDENTIALS": ref_for(spec, "GOOGLE_APPLICATION_CREDENTIALS")}},
                ["GOOGLE_APPLICATION_CREDENTIALS"])
    return [_p("G6", spec["mcp_path"], "bigquery", "service-account key file")]


def g6_npm_publish(spec, rng, sink):
    spec["workflows"]["publish-npm.yml"] = {
        "name": "Publish SDK", "on": {"release": {"types": ["published"]}}, "permissions": {"contents": "read"},
        "jobs": {"npm": {"runs-on": "ubuntu-latest", "steps": [
            {"uses": "actions/checkout@v4"},
            {"uses": "actions/setup-node@v4", "with": {"node-version": "22", "registry-url": "https://registry.npmjs.org"}},
            {"run": "npm ci && npm publish --access public", "env": {"NODE_AUTH_TOKEN": "${{ secrets.NPM_TOKEN }}"}}]}}}
    return [_p("G6", _wf_path("publish-npm.yml"), "Publish SDK/npm", "long-lived npm token")]


# ============================================================================ G7


def g7_new_server_env(spec, rng, sink):
    _add_server(spec, "datadog", {"command": "npx", "args": ["-y", "@winor30/mcp-server-datadog"],
                                  "env": {"DATADOG_API_KEY": ref_for(spec, "DATADOG_API_KEY"),
                                          "DATADOG_APP_KEY": ref_for(spec, "DATADOG_APP_KEY"), "DATADOG_SITE": "datadoghq.com"}},
                ["DATADOG_API_KEY", "DATADOG_APP_KEY"])
    return [_p("G7", spec["mcp_path"], "datadog", "new observability server")]


@requires("deploy")
def g7_prod_secret(spec, rng, sink):
    f, job = _deploy_job(spec)
    _step_env(spec["workflows"][f]["jobs"][job]["steps"][-1], "DATADOG_API_KEY", "${{ secrets.DATADOG_API_KEY }}")
    return [_p("G7", _wf_path(f), gha_component(spec, f, job), "new secret in production deploy")]


def g7_remote_oauth(spec, rng, sink):
    name = _new_remote(spec, rng)
    _add_server(spec, name, {"type": "http", "url": EXTRA_REMOTES[name]})
    return [_p("G7", spec["mcp_path"], name, "new remote server with delegated OAuth")]


def g7_env_decl(spec, rng, sink):
    spec["env_example"][0][1].append("STRIPE_SECRET_KEY")
    return [_p("G7", ".env.example", ".env.example", "new declared credential")]


def g7_notify_job(spec, rng, sink):
    spec["workflows"]["ci.yml"]["jobs"]["notify"] = {
        "runs-on": "ubuntu-latest", "needs": ["test", "lint"], "if": "${{ failure() }}", "permissions": {},
        "steps": [{"run": 'curl -sS -X POST -d \'{"text":"CI failed"}\' "$SLACK_WEBHOOK_URL"',
                   "env": {"SLACK_WEBHOOK_URL": "${{ secrets.SLACK_WEBHOOK_URL }}"}}]}
    return [_p("G7", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "notify"), "new notify job with webhook secret")]


def g7_header_ref(spec, rng, sink):
    _add_server(spec, "hubspot", {"type": "http", "url": "https://mcp.hubspot.com/anthropic",
                                  "headers": {"Authorization": "Bearer " + ref_for(spec, "HUBSPOT_PRIVATE_APP_TOKEN")}},
                ["HUBSPOT_PRIVATE_APP_TOKEN"])
    return [_p("G7", spec["mcp_path"], "hubspot", "new CRM server with private app token")]


@requires("eval")
def g7_eval_extra(spec, rng, sink):
    _step_env(spec["workflows"]["eval.yml"]["jobs"]["eval"]["steps"][-1], "OPENAI_API_KEY", "${{ secrets.EVAL_OPENAI_API_KEY }}")
    return [_p("G7", _wf_path("eval.yml"), gha_component(spec, "eval.yml", "eval"), "judge model key added")]


# ============================================================================ G8


@requires("cred_server")
def g8_remove_server(spec, rng, sink):
    srv, _ = _cred_server(spec, rng)
    if srv == "github":
        srv = next(n for n in sorted(spec["servers"]) if n in CRED_SERVERS)
    del spec["servers"][srv]
    return [_p("G8", spec["mcp_path"], srv, "server removed; credential still declared")]


@requires("eval")
def g8_remove_eval_wf(spec, rng, sink):
    comp = gha_component(spec, "eval.yml", "eval")
    del spec["workflows"]["eval.yml"]
    return [_p("G8", _wf_path("eval.yml"), comp, "eval workflow deleted")]


@requires("codecov")
def g8_remove_codecov(spec, rng, sink):
    steps = spec["workflows"]["ci.yml"]["jobs"]["test"]["steps"]
    spec["workflows"]["ci.yml"]["jobs"]["test"]["steps"] = [s for s in steps if "codecov" not in str(s.get("uses", ""))]
    return [_p("G8", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "test"), "coverage upload removed")]


@requires("deploy")
def g8_remove_deploy_wf(spec, rng, sink):
    f, job = _deploy_job(spec)
    comp = gha_component(spec, f, job)
    del spec["workflows"][f]
    return [_p("G8", _wf_path(f), comp, "deploy workflow removed")]


@requires("remote_oauth")
def g8_remove_remote(spec, rng, sink):
    name = next(n for n in sorted(spec["servers"]) if n in REMOTE_OAUTH)
    del spec["servers"][name]
    return [_p("G8", spec["mcp_path"], name, "remote server removed")]


def g8_remove_github(spec, rng, sink):
    del spec["servers"]["github"]
    return [_p("G8", spec["mcp_path"], "github", "github server removed")]


PLANTED: dict[str, list[Callable]] = {
    "G1": [g1_env_literal, g1_conn_string, g1_header_literal, g1_workflow_env, g1_run_token, g1_args_key, g1_with_literal],
    "G2": [g2_job_pr_write, g2_deploy_add, g2_remove_workflow_perms, g2_toolsets, g2_ci_contents_write, g2_eval_issues,
           g2_docker_attest, g2_lint_checks_write],
    "G3": [g3_job_write_all, g3_admin_role, g3_toolsets_all, g3_wf_write_all, g3_snowflake_admin, g3_gcp_admin_sa],
    "G4": [g4_drop_mcp_rule, g4_drop_github_rule, g4_narrow_github_rule, g4_typo, g4_delete_codeowners, g4_explicit_unowned],
    "G5": [g5_second_server_same_pat, g5_eval_secret_in_ci, g5_second_mcp_file, g5_shared_role, g5_codecov_two_jobs, g5_slack_reuse],
    "G6": [g6_aws_static_replace, g6_backup_job, g6_gcp_sa_key, g6_azure_creds, g6_pypi_token, g6_mcp_aws, g6_mcp_bigquery, g6_npm_publish],
    "G7": [g7_new_server_env, g7_prod_secret, g7_remote_oauth, g7_env_decl, g7_notify_job, g7_header_ref, g7_eval_extra],
    "G8": [g8_remove_server, g8_remove_eval_wf, g8_remove_codecov, g8_remove_deploy_wf, g8_remove_remote, g8_remove_github],
}


# ============================================================================ diff pairs
# (variant, expected labels). Labels follow SPEC.md §5 by construction.


def dp_benign_text(spec, rng, sink):
    spec["ctx"]["project"] = spec["ctx"]["project"]  # README regenerated with a new team name below
    spec["team"] = "agents" if spec["team"] != "agents" else "devex"
    for st in spec["workflows"]["ci.yml"]["jobs"]["test"]["steps"]:
        if "run" in st and st["run"].startswith("pytest"):
            st["name"] = st.get("name", "") + " (verbose)"
            st["run"] = st["run"] + " -v"
    return []


def dp_scope_reduce(spec, rng, sink):
    spec["workflows"]["ci.yml"]["permissions"] = {}
    return []


@requires("cred_server")
def dp_rename_server(spec, rng, sink):
    srv, _ = _cred_server(spec, rng)
    spec["servers"] = {(srv + "-mcp" if k == srv else k): v for k, v in spec["servers"].items()}
    return []


@requires("eval")
def dp_new_job_reuse_eval(spec, rng, sink):
    spec["workflows"]["ci.yml"]["jobs"]["smoke"] = {"runs-on": "ubuntu-latest", "needs": "test", "steps": [
        {"uses": "actions/checkout@v4"},
        {"run": "python -m evals.run --suite smoke", "env": {"ANTHROPIC_API_KEY": "${{ secrets.EVAL_ANTHROPIC_API_KEY }}"}}]}
    return [_p("G5", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "smoke"), "eval key shared"),
            _p("G7", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "smoke"), "new job token")]


def dp_rename_job(spec, rng, sink):
    jobs = spec["workflows"]["ci.yml"]["jobs"]
    spec["workflows"]["ci.yml"]["jobs"] = {("static-analysis" if k == "lint" else k): v for k, v in jobs.items()}
    return [_p("G7", _wf_path("ci.yml"), gha_component(spec, "ci.yml", "static-analysis"), "new job token"),
            _p("G8", _wf_path("ci.yml"), "CI/lint", "old job token dormant")]


@requires("cred_server")
def dp_swap_remote(spec, rng, sink):
    planted = g8_remove_server(spec, rng, sink)
    planted += g7_remote_oauth(spec, rng, sink)
    return planted


DIFF_PAIRS: list[tuple[Callable, list[str]]] = [
    (dp_benign_text, []),
    (dp_scope_reduce, []),
    (dp_rename_server, []),
    (g2_deploy_add, ["G2"]),
    (g7_prod_secret, ["G7"]),
    (g8_remove_server, ["G8"]),
    (g6_aws_static_replace, ["G6", "G7", "G8"]),
    (g3_job_write_all, ["G2", "G3"]),
    (g3_toolsets_all, ["G2", "G3"]),
    (g4_delete_codeowners, ["G4"]),
    (g5_second_server_same_pat, ["G5"]),
    (g1_env_literal, ["G1"]),
    (dp_swap_remote, ["G7", "G8"]),
    (g2_remove_workflow_perms, ["G2"]),
    (dp_new_job_reuse_eval, ["G5", "G7"]),
    (dp_rename_job, ["G7", "G8"]),
]


def requirements(fn) -> set[str]:
    return set(getattr(fn, "requires", set()))


__all__ = ["PLANTED", "DIFF_PAIRS", "Sink", "requirements", "CATALOG"]
