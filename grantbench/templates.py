"""Realistic repository templates for GrantBench (agent stacks: MCP + GHA + .env).

A *spec* is a plain dict describing a repository; ``render(spec)`` turns it into
``{relative_path: text}``. Mutations in ``grantbench.mutations`` edit specs.
"""

from __future__ import annotations

import copy
import json
import random
import re
import string
from typing import Any

import yaml

PROJECTS = [
    "support-copilot", "repo-gardener", "docs-assistant", "sales-ops-agent", "incident-bot",
    "data-analyst-agent", "release-helper", "triage-agent", "onboarding-buddy", "billing-concierge",
    "qa-pilot", "research-scout",
]
ORGS = ["acme", "globex", "initech", "umbrella", "hooli", "stark-labs", "wayne-ent", "tyrell", "cyberdyne", "soylent"]

L = {
    "en": {
        "checkout": "Check out repository",
        "setup": "Set up Python",
        "install": "Install dependencies",
        "test": "Run unit tests",
        "lint": "Lint",
        "deploy": "Deploy",
        "creds": "Configure cloud credentials",
        "eval": "Run agent evaluation suite",
        "build": "Build and push image",
        "login": "Log in to registry",
        "publish": "Publish package",
        "codecov": "Upload coverage",
        "notify": "Notify channel",
        "ci_comment": ["Continuous integration for {p}.", "Keep permissions minimal; see SECURITY.md."],
        "deploy_comment": ["Deploys {p} using short-lived OIDC credentials (no stored cloud keys)."],
        "eval_comment": ["Nightly evaluation of the agent against the regression set."],
        "docker_comment": ["Builds the container image and pushes it to GHCR."],
        "release_comment": ["Publishes releases via trusted publishing."],
        "env_header": "# Copy this file to .env and fill in values. Never commit real secrets.",
        "env_mcp": "# Credentials used by MCP servers (see .mcp config)",
        "env_app": "# Application settings",
        "codeowners_header": "# Code owners: agent credentials and CI must be reviewed by the owning team.",
        "readme": (
            "# {p}\n\n{p} is an internal AI agent maintained by the {o} {team} team. It uses MCP servers "
            "for tool access and runs its evaluation suite in GitHub Actions.\n\n## Setup\n\n1. Copy `.env.example` to `.env` and fill in the values.\n"
            "2. Start the agent with `make dev`.\n\n## Security\n\nCredentials are referenced from the environment; do not paste tokens into config files.\n"
        ),
        "vscode_comment": "// MCP servers for the {p} workspace",
    },
    "ja": {
        "checkout": "リポジトリをチェックアウト",
        "setup": "Python をセットアップ",
        "install": "依存関係をインストール",
        "test": "ユニットテストを実行",
        "lint": "静的解析",
        "deploy": "デプロイ",
        "creds": "クラウド認証情報を設定",
        "eval": "エージェント評価スイートを実行",
        "build": "イメージをビルドして push",
        "login": "レジストリにログイン",
        "publish": "パッケージを公開",
        "codecov": "カバレッジをアップロード",
        "notify": "チャンネルに通知",
        "ci_comment": ["{p} の CI。", "権限は最小限にすること（SECURITY.md 参照）。"],
        "deploy_comment": ["{p} を OIDC の短期認証でデプロイする（クラウドの鍵は保存しない）。"],
        "eval_comment": ["回帰セットに対するエージェントの夜間評価。"],
        "docker_comment": ["コンテナイメージをビルドして GHCR に push する。"],
        "release_comment": ["Trusted Publishing でリリースを公開する。"],
        "env_header": "# このファイルを .env にコピーして値を設定してください。本物の秘密はコミットしないこと。",
        "env_mcp": "# MCP サーバが使う認証情報（.mcp の設定を参照）",
        "env_app": "# アプリケーション設定",
        "codeowners_header": "# コードオーナー: エージェントの認証情報と CI は担当チームのレビュー必須。",
        "readme": (
            "# {p}\n\n{p} は {o} の {team} チームが保守する社内 AI エージェントです。ツール接続には MCP サーバを使い、"
            "評価スイートは GitHub Actions で実行します。\n\n## セットアップ\n\n1. `.env.example` を `.env` にコピーして値を設定します。\n"
            "2. `make dev` でエージェントを起動します。\n\n## セキュリティ\n\n認証情報は環境変数から参照します。設定ファイルにトークンを貼り付けないでください。\n"
        ),
        "vscode_comment": "// {p} ワークスペースの MCP サーバ",
    },
}

TEAMS = ["platform", "ai-platform", "devex", "agents", "ml-infra"]


# ----------------------------------------------------------------------------
# fake secret material (always contains FAKE; never a real credential shape)
# ----------------------------------------------------------------------------

def _rand(rng: random.Random, n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def fake_secret(rng: random.Random, kind: str) -> str:
    if kind == "openai":
        return "sk-FAKE" + _rand(rng, 40)
    if kind == "anthropic":
        return "sk-ant-FAKE" + _rand(rng, 40)
    if kind == "github":
        return "ghp_FAKE" + _rand(rng, 32)
    if kind == "slack":
        return "xoxb-FAKE-" + _rand(rng, 12, string.digits) + "-" + _rand(rng, 24)
    if kind == "aws":
        return "AKIAFAKE" + _rand(rng, 12, string.ascii_uppercase + string.digits)
    if kind == "password":
        return "FAKEpw" + _rand(rng, 14)
    return "FAKE" + _rand(rng, 28)


# ----------------------------------------------------------------------------
# MCP server catalog. Each returns (server_dict, [declared env names]).
# `ref(name)` renders an environment reference in the file's dialect.
# ----------------------------------------------------------------------------

def srv_github(ref, ctx):
    return {
        "command": "docker",
        "args": ["run", "-i", "--rm", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "-e", "GITHUB_TOOLSETS",
                 "ghcr.io/github/github-mcp-server"],
        "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": ref("GITHUB_PERSONAL_ACCESS_TOKEN"), "GITHUB_TOOLSETS": "repos,issues"},
    }, ["GITHUB_PERSONAL_ACCESS_TOKEN"]


def srv_slack(ref, ctx):
    return {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-slack"],
        "env": {"SLACK_BOT_TOKEN": ref("SLACK_BOT_TOKEN"), "SLACK_TEAM_ID": "T0" + ctx["team_id"],
                "SLACK_CHANNEL_IDS": "C0" + ctx["team_id"]},
    }, ["SLACK_BOT_TOKEN"]


def srv_postgres(ref, ctx):
    return {
        "command": "npx",
        "args": ["-y", "@modelcontextprotocol/server-postgres",
                 "postgresql://readonly:" + ref("PG_READONLY_PASSWORD") + f"@db.staging.{ctx['org']}.internal:5432/{ctx['db']}"],
    }, ["PG_READONLY_PASSWORD"]


def srv_brave(ref, ctx):
    return {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-brave-search"],
            "env": {"BRAVE_API_KEY": ref("BRAVE_API_KEY")}}, ["BRAVE_API_KEY"]


def srv_tavily(ref, ctx):
    return {"command": "npx", "args": ["-y", "tavily-mcp@0.2.4"], "env": {"TAVILY_API_KEY": ref("TAVILY_API_KEY")}}, ["TAVILY_API_KEY"]


def srv_notion(ref, ctx):
    return {"command": "npx", "args": ["-y", "@notionhq/notion-mcp-server"],
            "env": {"NOTION_TOKEN": ref("NOTION_TOKEN")}}, ["NOTION_TOKEN"]


def srv_supabase(ref, ctx):
    return {"command": "npx", "args": ["-y", "@supabase/mcp-server-supabase@latest", "--read-only",
                                       f"--project-ref={ctx['supabase_ref']}"],
            "env": {"SUPABASE_ACCESS_TOKEN": ref("SUPABASE_ACCESS_TOKEN")}}, ["SUPABASE_ACCESS_TOKEN"]


def srv_linear(ref, ctx):
    return {"type": "http", "url": "https://mcp.linear.app/mcp"}, []


def srv_sentry(ref, ctx):
    return {"type": "http", "url": "https://mcp.sentry.dev/mcp"}, []


def srv_atlassian(ref, ctx):
    return {"type": "sse", "url": "https://mcp.atlassian.com/v1/sse"}, []


def srv_filesystem(ref, ctx):
    return {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "./docs", "./runbooks"]}, []


def srv_fetch(ref, ctx):
    return {"command": "uvx", "args": ["mcp-server-fetch"]}, []


def srv_memory(ref, ctx):
    return {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"],
            "env": {"MEMORY_FILE_PATH": "./.agent/memory.json"}}, []


CATALOG = {
    "slack": srv_slack,
    "postgres": srv_postgres,
    "brave-search": srv_brave,
    "tavily": srv_tavily,
    "notion": srv_notion,
    "supabase": srv_supabase,
    "linear": srv_linear,
    "sentry": srv_sentry,
    "atlassian": srv_atlassian,
    "filesystem": srv_filesystem,
    "fetch": srv_fetch,
    "memory": srv_memory,
}
REMOTE_OAUTH = {"linear", "sentry", "atlassian"}
CRED_SERVERS = {"slack", "postgres", "brave-search", "tavily", "notion", "supabase"}


# ----------------------------------------------------------------------------
# workflows
# ----------------------------------------------------------------------------

def _steps_checkout(t):
    return [{"name": t["checkout"], "uses": "actions/checkout@v4"}]


def wf_ci(ctx, t, codecov: bool):
    test_steps = _steps_checkout(t) + [
        {"name": t["setup"], "uses": "actions/setup-python@v5", "with": {"python-version": "3.12"}},
        {"name": t["install"], "run": "pip install -e '.[test]'"},
        {"name": t["test"], "run": "pytest -q --cov=src --cov-report=xml"},
    ]
    if codecov:
        test_steps.append({"name": t["codecov"], "uses": "codecov/codecov-action@v4",
                           "with": {"token": "${{ secrets.CODECOV_TOKEN }}", "files": "coverage.xml"}})
    return {
        "name": "CI",
        "on": {"push": {"branches": ["main"]}, "pull_request": None},
        "permissions": {"contents": "read"},
        "jobs": {
            "test": {"runs-on": "ubuntu-latest", "steps": test_steps},
            "lint": {"runs-on": "ubuntu-latest", "steps": _steps_checkout(t) + [
                {"name": t["lint"], "run": "pipx run ruff check ."}]},
        },
    }


def wf_deploy_aws(ctx, t):
    return {
        "name": "Deploy",
        "on": {"push": {"branches": ["main"]}, "workflow_dispatch": None},
        "permissions": {"contents": "read"},
        "concurrency": {"group": "deploy-production", "cancel-in-progress": False},
        "jobs": {"deploy": {
            "runs-on": "ubuntu-latest",
            "environment": "production",
            "permissions": {"contents": "read", "id-token": "write"},
            "steps": _steps_checkout(t) + [
                {"name": t["creds"], "uses": "aws-actions/configure-aws-credentials@v4",
                 "with": {"role-to-assume": f"arn:aws:iam::{ctx['acct']}:role/{ctx['project']}-deploy",
                          "aws-region": ctx["region"]}},
                {"name": t["deploy"], "run": f"aws ecs update-service --cluster {ctx['project']} --service api --force-new-deployment"},
            ],
        }},
    }


def wf_deploy_gcp(ctx, t):
    return {
        "name": "Deploy",
        "on": {"push": {"branches": ["main"]}},
        "permissions": {"contents": "read"},
        "jobs": {"deploy": {
            "runs-on": "ubuntu-latest",
            "environment": {"name": "production", "url": f"https://{ctx['project']}.{ctx['org']}.example"},
            "permissions": {"contents": "read", "id-token": "write"},
            "steps": _steps_checkout(t) + [
                {"name": t["creds"], "uses": "google-github-actions/auth@v2",
                 "with": {"workload_identity_provider": f"projects/{ctx['gcp_num']}/locations/global/workloadIdentityPools/github/providers/{ctx['project']}",
                          "service_account": f"deployer@{ctx['gcp_project']}.iam.gserviceaccount.com"}},
                {"name": t["deploy"], "run": f"gcloud run deploy {ctx['project']} --source . --region us-central1"},
            ],
        }},
    }


def wf_deploy_azure(ctx, t):
    return {
        "name": "Deploy",
        "on": {"push": {"branches": ["main"]}},
        "permissions": {"contents": "read"},
        "jobs": {"deploy": {
            "runs-on": "ubuntu-latest",
            "environment": "production",
            "permissions": {"contents": "read", "id-token": "write"},
            "steps": _steps_checkout(t) + [
                {"name": t["creds"], "uses": "azure/login@v2",
                 "with": {"client-id": "${{ secrets.AZURE_CLIENT_ID }}", "tenant-id": "${{ secrets.AZURE_TENANT_ID }}",
                          "subscription-id": "${{ secrets.AZURE_SUBSCRIPTION_ID }}"}},
                {"name": t["deploy"], "run": f"az webapp up --name {ctx['project']}"},
            ],
        }},
    }


def wf_release_pypi(ctx, t):
    return {
        "name": "Release",
        "on": {"release": {"types": ["published"]}},
        "permissions": {"contents": "read"},
        "jobs": {"publish": {
            "runs-on": "ubuntu-latest",
            "environment": "pypi",
            "permissions": {"contents": "read", "id-token": "write"},
            "steps": _steps_checkout(t) + [
                {"name": t["install"], "run": "python -m pip install build && python -m build"},
                {"name": t["publish"], "uses": "pypa/gh-action-pypi-publish@release/v1"},
            ],
        }},
    }


def wf_eval(ctx, t):
    return {
        "name": "Agent eval",
        "on": {"schedule": [{"cron": "17 3 * * *"}], "workflow_dispatch": None},
        "permissions": {"contents": "read"},
        "jobs": {"eval": {
            "runs-on": "ubuntu-latest",
            "environment": "staging",
            "timeout-minutes": 60,
            "steps": _steps_checkout(t) + [
                {"name": t["install"], "run": "pip install -e '.[eval]'"},
                {"name": t["eval"], "run": "python -m evals.run --suite regression --report evals/report.json",
                 "env": {"ANTHROPIC_API_KEY": "${{ secrets.EVAL_ANTHROPIC_API_KEY }}"}},
            ],
        }},
    }


def wf_docker(ctx, t):
    return {
        "name": "Container image",
        "on": {"push": {"branches": ["main"], "tags": ["v*"]}},
        "permissions": {"contents": "read"},
        "jobs": {"image": {
            "runs-on": "ubuntu-latest",
            "permissions": {"contents": "read", "packages": "write"},
            "steps": _steps_checkout(t) + [
                {"name": t["login"], "uses": "docker/login-action@v3",
                 "with": {"registry": "ghcr.io", "username": "${{ github.actor }}", "password": "${{ secrets.GITHUB_TOKEN }}"}},
                {"name": t["build"], "uses": "docker/build-push-action@v6",
                 "with": {"push": True, "tags": f"ghcr.io/{ctx['org']}/{ctx['project']}:latest"}},
            ],
        }},
    }


DEPLOYS = {"deploy_aws": wf_deploy_aws, "deploy_gcp": wf_deploy_gcp, "deploy_azure": wf_deploy_azure,
           "release_pypi": wf_release_pypi}
DEPLOY_FILES = {"deploy_aws": "deploy.yml", "deploy_gcp": "deploy.yml", "deploy_azure": "deploy.yml",
                "release_pypi": "release.yml"}


# ----------------------------------------------------------------------------
# base repository spec
# ----------------------------------------------------------------------------

def make_base(rng: random.Random, lang: str, require: set[str] | None = None) -> dict[str, Any]:
    require = set(require or ())
    t = L[lang]
    project = rng.choice(PROJECTS)
    org = rng.choice(ORGS)
    ctx = {
        "project": project, "org": org, "acct": "".join(rng.choice(string.digits) for _ in range(12)),
        "region": rng.choice(["us-east-1", "eu-west-1", "ap-northeast-1"]),
        "gcp_project": f"{org}-{project}"[:28], "gcp_num": str(rng.randint(10**11, 10**12 - 1)),
        "team_id": _rand(rng, 8, string.ascii_uppercase + string.digits), "db": project.replace("-", "_"),
        "supabase_ref": _rand(rng, 20, string.ascii_lowercase),
    }
    team = rng.choice(TEAMS)

    # MCP file dialect
    dialect = "vscode" if "vscode" in require else rng.choices(["claude", "cursor", "vscode"], [2, 1, 1])[0]
    if "no_vscode" in require and dialect == "vscode":
        dialect = "claude"
    mcp_path = {"claude": ".mcp.json", "cursor": ".cursor/mcp.json", "vscode": ".vscode/mcp.json"}[dialect]
    root = "servers" if dialect == "vscode" else "mcpServers"
    ref = (lambda n: "${env:" + n + "}") if dialect == "vscode" else (lambda n: "${" + n + "}")

    pool = sorted(CATALOG)
    k = rng.randint(2, 3)
    chosen = rng.sample(pool, k)
    if "remote_oauth" in require and not any(c in REMOTE_OAUTH for c in chosen):
        chosen.append(rng.choice(sorted(REMOTE_OAUTH)))
    if "cred_server" in require and not any(c in CRED_SERVERS for c in chosen):
        chosen.append(rng.choice(sorted(CRED_SERVERS)))
    for r in sorted(require):
        if r.startswith("server:") and r[7:] in CATALOG and r[7:] not in chosen:
            chosen.append(r[7:])
    servers: dict[str, Any] = {}
    declared: list[str] = []
    s, d = srv_github(ref, ctx)
    servers["github"] = s
    declared += d
    for name in sorted(chosen):
        s, d = CATALOG[name](ref, ctx)
        if dialect == "vscode" and "command" in s:
            s = dict({"type": "stdio"}, **s)
        servers[name] = s
        declared += d

    workflows: dict[str, Any] = {}
    comments: dict[str, list[str]] = {}
    workflows["ci.yml"] = wf_ci(ctx, t, codecov=("codecov" in require) or rng.random() < 0.4)
    comments["ci.yml"] = [c.format(p=project) for c in t["ci_comment"]]
    deploy_choice = next((r for r in ("deploy_aws", "deploy_gcp", "deploy_azure", "release_pypi") if r in require), None)
    if deploy_choice is None and "deploy" in require:
        deploy_choice = rng.choice(["deploy_aws", "deploy_gcp", "deploy_azure"])
    if deploy_choice is None and "no_deploy" not in require:
        deploy_choice = rng.choice(["deploy_aws", "deploy_gcp", "deploy_azure", "release_pypi", None])
    if deploy_choice:
        f = DEPLOY_FILES[deploy_choice]
        workflows[f] = DEPLOYS[deploy_choice](ctx, t)
        comments[f] = [c.format(p=project) for c in (t["release_comment"] if deploy_choice == "release_pypi" else t["deploy_comment"])]
    if "eval" in require or rng.random() < 0.6:
        workflows["eval.yml"] = wf_eval(ctx, t)
        comments["eval.yml"] = list(t["eval_comment"])
    if "docker" in require or rng.random() < 0.35:
        workflows["docker.yml"] = wf_docker(ctx, t)
        comments["docker.yml"] = list(t["docker_comment"])

    owners_ai = f"@{org}/{team}"
    owners_platform = f"@{org}/platform"
    mcp_rule = "/.cursor/" if dialect == "cursor" else ("/.vscode/" if dialect == "vscode" else "/.mcp.json")
    codeowners = [
        ("/.github/", [owners_platform]),
        (mcp_rule, [owners_ai]),
        ("/.env.example", [owners_ai]),
        ("/src/", [owners_ai]),
    ]
    env_example = [("MCP", declared), ("APP", ["LOG_LEVEL", "AGENT_MODEL", "PORT"])]

    return {
        "ctx": ctx, "lang": lang, "team": team, "dialect": dialect, "mcp_path": mcp_path, "mcp_root": root,
        "servers": servers, "workflows": workflows, "wf_comments": comments,
        "codeowners": codeowners, "env_example": env_example, "extra_mcp_files": {},
        "extra_files": {},
    }


def ref_for(spec: dict[str, Any], name: str) -> str:
    return "${env:" + name + "}" if spec["dialect"] == "vscode" else "${" + name + "}"


def gha_component(spec: dict[str, Any], wf_file: str, job: str) -> str:
    return f"{spec['workflows'][wf_file]['name']}/{job}"


# ----------------------------------------------------------------------------
# rendering
# ----------------------------------------------------------------------------

class _Dumper(yaml.SafeDumper):
    pass


def _str_rep(dumper, data):
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper.add_representer(str, _str_rep)


def _none_rep(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:null", "")


_Dumper.add_representer(type(None), _none_rep)


def render_workflow(wf: dict[str, Any], comments: list[str]) -> str:
    body = yaml.dump(wf, Dumper=_Dumper, sort_keys=False, default_flow_style=False, allow_unicode=True, width=200)
    body = re.sub(r"^'on':", "on:", body, flags=re.M)
    out = []
    for line in body.splitlines():
        if line == "jobs:":
            out.append("")
        out.append(line.rstrip())
    head = "".join(f"# {c}\n" for c in comments)
    return head + "\n".join(out) + "\n"


def render_mcp(spec: dict[str, Any], servers: dict[str, Any], dialect: str, root: str) -> str:
    doc: dict[str, Any] = {}
    if dialect == "vscode":
        ids = sorted(set(re.findall(r"\$\{input:([A-Za-z0-9_.-]+)\}", json.dumps(servers))))
        doc["inputs"] = [{"type": "promptString", "id": i, "description": i.replace("_", " "), "password": True} for i in ids]
    doc[root] = servers
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if dialect == "vscode":
        text = L[spec["lang"]]["vscode_comment"].format(p=spec["ctx"]["project"]) + "\n" + text
    return text


def render_env_example(spec: dict[str, Any]) -> str:
    t = L[spec["lang"]]
    lines = [t["env_header"], ""]
    for section, names in spec["env_example"]:
        lines.append(t["env_mcp"] if section == "MCP" else t["env_app"])
        for n in names:
            if n == "LOG_LEVEL":
                lines.append("LOG_LEVEL=info")
            elif n == "PORT":
                lines.append("PORT=8080")
            elif n == "AGENT_MODEL":
                lines.append("AGENT_MODEL=claude-sonnet-5-5")
            else:
                lines.append(f"{n}=")
        lines.append("")
    return "\n".join(lines)


def render_codeowners(spec: dict[str, Any]) -> str:
    t = L[spec["lang"]]
    lines = [t["codeowners_header"]]
    for pattern, owners in spec["codeowners"]:
        lines.append(f"{pattern:<24} {' '.join(owners)}".rstrip())
    return "\n".join(lines) + "\n"


def render(spec: dict[str, Any]) -> dict[str, str]:
    ctx = spec["ctx"]
    t = L[spec["lang"]]
    files: dict[str, str] = {}
    files["README.md"] = t["readme"].format(p=ctx["project"], o=ctx["org"], team=spec["team"])
    files[".gitignore"] = ".env\n.venv/\n__pycache__/\n.agent/\n"
    files["pyproject.toml"] = (
        f'[project]\nname = "{ctx["project"]}"\nversion = "0.4.{len(ctx["project"]) % 9}"\n'
        'requires-python = ">=3.11"\ndependencies = ["anthropic>=0.60", "mcp>=1.10", "httpx>=0.27"]\n\n'
        '[project.optional-dependencies]\ntest = ["pytest", "pytest-cov"]\neval = ["pandas"]\n'
    )
    pkg = ctx["project"].replace("-", "_")
    files[f"src/{pkg}/__init__.py"] = '"""Agent entry point."""\n'
    files[f"src/{pkg}/agent.py"] = (
        "import os\n\nfrom anthropic import Anthropic\n\n\n"
        "def client() -> Anthropic:\n    # key comes from the environment, never from source\n"
        "    return Anthropic(api_key=os.environ[\"ANTHROPIC_API_KEY\"])\n"
    )
    if spec["codeowners"] is not None:
        files[".github/CODEOWNERS"] = render_codeowners(spec)
    files[spec["mcp_path"]] = render_mcp(spec, spec["servers"], spec["dialect"], spec["mcp_root"])
    for path, (servers, dialect, root) in spec["extra_mcp_files"].items():
        files[path] = render_mcp(spec, servers, dialect, root)
    for fname, wf in spec["workflows"].items():
        files[f".github/workflows/{fname}"] = render_workflow(wf, spec["wf_comments"].get(fname, []))
    files[".env.example"] = render_env_example(spec)
    files.update(spec["extra_files"])
    return files


def clone(spec: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(spec)


# ----------------------------------------------------------------------------
# near-misses: legitimate settings that look credential-ish. Applied to every
# base so that the clean set measures false positives on realistic noise.
# ----------------------------------------------------------------------------

def add_near_misses(spec: dict[str, Any], rng: random.Random) -> None:
    servers = spec["servers"]
    gh = servers["github"]
    options = ["gh_host", "proxy", "timeouts", "token_cache", "lint_none", "if_expr", "publishable", "input_header"]
    picks = rng.sample(options, 3)
    if "gh_host" in picks:
        gh["env"]["GITHUB_HOST"] = "https://github.com"
    if "proxy" in picks:
        target = next((s for n, s in sorted(servers.items()) if n != "github" and isinstance(s.get("env"), dict)), gh)
        target.setdefault("env", {})["HTTPS_PROXY"] = "http://proxy.internal:3128"
    if "timeouts" in picks:
        gh["env"]["API_TIMEOUT_MS"] = "30000"
    if "token_cache" in picks:
        gh["env"]["TOKEN_CACHE_DIR"] = "./.cache/tokens"
    if "lint_none" in picks:
        spec["workflows"]["ci.yml"]["jobs"]["lint"]["permissions"] = {}
    if "if_expr" in picks:
        steps = spec["workflows"]["ci.yml"]["jobs"]["test"]["steps"]
        steps[-1]["if"] = "${{ github.event_name == 'push' }}"
    if "publishable" in picks:
        spec["extra_files"]["web/.env.example"] = "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=\nNEXT_PUBLIC_SITE_URL=http://localhost:3000\n"
    if "input_header" in picks and spec["dialect"] == "vscode":
        servers["github-remote"] = {"type": "http", "url": "https://api.githubcopilot.com/mcp/",
                                    "headers": {"Authorization": "Bearer ${input:github_mcp_pat}"}}
