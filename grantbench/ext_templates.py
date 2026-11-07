"""dev-ext templates: agent stacks deployed with docker-compose, Kubernetes and Terraform.

Specs are plain dicts; ``render_ext(spec)`` -> {path: text}. Dummy secrets follow
the real formats (prefix, length, alphabet) with a FAKE marker inside (D-018).
"""

from __future__ import annotations

import copy
import random
import string
from typing import Any

import yaml

from .templates import ORGS, PROJECTS, TEAMS, _Dumper

B32 = string.ascii_uppercase + "234567"
ALNUM = string.ascii_letters + string.digits
URLSAFE = ALNUM + "-_"

T = {
    "en": {
        "compose_head": "# Local stack for {p}: agent API, worker, Postgres, Redis.\n# Secrets come from the environment or Docker secrets; never hard-code them.\n",
        "k8s_head": "# {p} — production manifests (namespace {ns}).\n",
        "tf_head": "# {p}: IAM for the agent runtime and CI deploys.\n",
        "readme": "# {p}\n\n{p} is an AI agent service run by the {o} {team} team.\n\n- `compose.yaml`: local development stack\n- `deploy/k8s/`: Kubernetes manifests\n- `infra/`: Terraform for cloud IAM\n\nCredentials are injected at runtime (Docker secrets, Kubernetes Secrets managed by External Secrets, workload identity).\n",
        "env_head": "# Copy to .env for local runs. Never commit real values.",
        "codeowners": "# Owners for deployment and identity configuration",
    },
    "ja": {
        "compose_head": "# {p} のローカル環境: エージェント API、ワーカー、Postgres、Redis。\n# 秘密は環境変数か Docker secrets から渡す。直書き禁止。\n",
        "k8s_head": "# {p} の本番マニフェスト（namespace {ns}）。\n",
        "tf_head": "# {p}: エージェント実行環境と CI デプロイ用の IAM。\n",
        "readme": "# {p}\n\n{p} は {o} の {team} チームが運用する AI エージェントサービスです。\n\n- `compose.yaml`: ローカル開発用スタック\n- `deploy/k8s/`: Kubernetes マニフェスト\n- `infra/`: クラウド IAM の Terraform\n\n認証情報は実行時に注入します（Docker secrets、External Secrets 管理の Kubernetes Secret、ワークロード ID）。\n",
        "env_head": "# ローカル実行用に .env へコピー。実値はコミットしないこと。",
        "codeowners": "# デプロイ設定と身分設定のオーナー",
    },
}


def _r(rng: random.Random, n: int, alphabet: str = ALNUM) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


def real_fake(rng: random.Random, kind: str) -> str:
    """Format-faithful, certainly-invalid dummies (FAKE marker inside the body)."""
    if kind == "anthropic":   # sk-ant-api03- + 95 chars ending in AA (108 total)
        return "sk-ant-api03-FAKE" + _r(rng, 89, URLSAFE) + "AA"
    if kind == "openai":      # sk-proj- + 74 + T3BlbkFJ + 74
        return "sk-proj-FAKE" + _r(rng, 70, URLSAFE) + "T3BlbkFJ" + _r(rng, 74, URLSAFE)
    if kind == "github":      # ghp_ + 36 alnum
        return "ghp_FAKE" + _r(rng, 32)
    if kind == "aws_id":      # AKIA + 16 base32
        return "AKIAFAKE" + _r(rng, 12, B32)
    if kind == "aws_secret":  # 40 chars of base64 alphabet
        return "FAKE" + _r(rng, 36, ALNUM + "/+")
    if kind == "slack":       # xoxb-<11-13 digits>-<13 digits>-<24 alnum>
        return f"xoxb-{_r(rng, 11, string.digits)}-{_r(rng, 13, string.digits)}-FAKE{_r(rng, 20)}"
    if kind == "password":
        return "FAKE" + _r(rng, 20)
    raise ValueError(kind)


# ----------------------------------------------------------------------------- base

def make_ext_base(rng: random.Random, lang: str, require: set[str] | None = None) -> dict[str, Any]:
    require = set(require or ())
    project = rng.choice(PROJECTS)
    org = rng.choice(ORGS)
    team = rng.choice(TEAMS)
    cloud = "aws" if "aws" in require else ("gcp" if "gcp" in require else rng.choice(["aws", "gcp"]))
    ns = rng.choice(["agents", "ai-prod", "assistant", "agents-prod"])
    acct = _r(rng, 12, string.digits)
    gproj = f"{org}-{project}"[:28]
    ver = f"{rng.randint(1, 4)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}"
    img = f"ghcr.io/{org}/{project}:{ver}"

    compose = {
        "services": {
            "agent": {"image": img, "ports": ["8080:8080"], "depends_on": ["db", "redis"],
                      "environment": {"ANTHROPIC_API_KEY": "${ANTHROPIC_API_KEY}", "LOG_LEVEL": "info",
                                      "DATABASE_URL": "postgres://agent:${POSTGRES_PASSWORD}@db:5432/agent",
                                      "REDIS_HOST": "redis"}},
            "worker": {"image": img, "command": ["python", "-m", f"{project.replace('-', '_')}.worker"],
                       "environment": {"SLACK_BOT_TOKEN": "${SLACK_BOT_TOKEN}", "QUEUE_URL": "redis://redis:6379/0"}},
            "db": {"image": "postgres:16", "environment": {"POSTGRES_PASSWORD_FILE": "/run/secrets/pg_password"},
                   "secrets": ["pg_password"], "volumes": ["pgdata:/var/lib/postgresql/data"]},
            "redis": {"image": "redis:7-alpine"},
        },
        "secrets": {"pg_password": {"file": "./secrets/pg_password.txt"}},
        "volumes": {"pgdata": {}},
    }

    if cloud == "aws":
        sa_ann = {"eks.amazonaws.com/role-arn": f"arn:aws:iam::{acct}:role/{project}-runtime"}
    else:
        sa_ann = {"iam.gke.io/gcp-service-account": f"{project}@{gproj}.iam.gserviceaccount.com"}
    k8s = {
        "serviceaccount.yaml": [{"apiVersion": "v1", "kind": "ServiceAccount",
                                 "metadata": {"name": project, "namespace": ns, "annotations": sa_ann}}],
        "rbac.yaml": [
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
             "metadata": {"name": f"{project}-reader", "namespace": ns},
             "rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list"]},
                       {"apiGroups": ["coordination.k8s.io"], "resources": ["leases"], "verbs": ["get", "update"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
             "metadata": {"name": f"{project}-reader", "namespace": ns},
             "subjects": [{"kind": "ServiceAccount", "name": project, "namespace": ns}],
             "roleRef": {"kind": "Role", "name": f"{project}-reader", "apiGroup": "rbac.authorization.k8s.io"}},
        ],
        "deployment.yaml": [
            {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": project, "namespace": ns, "labels": {"app": project}},
             "spec": {"replicas": 3, "selector": {"matchLabels": {"app": project}},
                      "template": {"metadata": {"labels": {"app": project}},
                                   "spec": {"serviceAccountName": project, "containers": [{
                                       "name": "agent", "image": img, "ports": [{"containerPort": 8080}],
                                       "env": [{"name": "LOG_LEVEL", "value": "info"},
                                               {"name": "ANTHROPIC_API_KEY", "valueFrom": {"secretKeyRef": {"name": "llm-keys", "key": "ANTHROPIC_API_KEY"}}},
                                               {"name": "SLACK_BOT_TOKEN", "valueFrom": {"secretKeyRef": {"name": "slack-bot", "key": "token"}}}],
                                       "resources": {"limits": {"memory": "1Gi"}}}]}}}},
        ],
        "externalsecret.yaml": [
            {"apiVersion": "external-secrets.io/v1beta1", "kind": "ExternalSecret", "metadata": {"name": "llm-keys", "namespace": ns},
             "spec": {"secretStoreRef": {"name": "cluster-store", "kind": "ClusterSecretStore"}, "target": {"name": "llm-keys"},
                      "data": [{"secretKey": "ANTHROPIC_API_KEY", "remoteRef": {"key": f"{project}/anthropic"}}]}},
        ],
    }

    tf: dict[str, dict[str, str]] = {}
    if cloud == "aws":
        tf["oidc.tf"] = {"aws_iam_openid_connect_provider.github": '''resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}'''}
        tf["deploy.tf"] = {
            "data.aws_iam_policy_document.deploy_trust": f'''data "aws_iam_policy_document" "deploy_trust" {{
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {{
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }}
    condition {{
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:{org}/{project}:environment:production"]
    }}
  }}
}}''',
            "aws_iam_role.deploy": f'''resource "aws_iam_role" "deploy" {{
  name               = "{project}-deploy"
  assume_role_policy = data.aws_iam_policy_document.deploy_trust.json
}}''',
            "data.aws_iam_policy_document.deploy": f'''data "aws_iam_policy_document" "deploy" {{
  statement {{
    actions   = ["ecs:UpdateService", "ecs:DescribeServices"]
    resources = ["arn:aws:ecs:us-east-1:{acct}:service/{project}/*"]
  }}
}}''',
            "aws_iam_policy.deploy": f'''resource "aws_iam_policy" "deploy" {{
  name   = "{project}-deploy"
  policy = data.aws_iam_policy_document.deploy.json
}}''',
            "aws_iam_role_policy_attachment.deploy": '''resource "aws_iam_role_policy_attachment" "deploy" {
  role       = aws_iam_role.deploy.name
  policy_arn = aws_iam_policy.deploy.arn
}''',
        }
        tf["runtime.tf"] = {
            "aws_iam_role.runtime": f'''resource "aws_iam_role" "runtime" {{
  name = "{project}-runtime"
  assume_role_policy = jsonencode({{
    Version   = "2012-10-17"
    Statement = [{{ Effect = "Allow", Principal = {{ Service = "lambda.amazonaws.com" }}, Action = "sts:AssumeRole" }}]
  }})
}}''',
            "aws_iam_role_policy.runtime": f'''resource "aws_iam_role_policy" "runtime" {{
  name = "{project}-runtime"
  role = aws_iam_role.runtime.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{ Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::{project}-knowledge/*"] }},
      {{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = ["arn:aws:logs:us-east-1:{acct}:log-group:/aws/lambda/{project}:*"] }}
    ]
  }})
}}''',
            "aws_lambda_function.runtime": f'''resource "aws_lambda_function" "runtime" {{
  function_name = "{project}"
  role          = aws_iam_role.runtime.arn
  runtime       = "python3.12"
  handler       = "app.handler"
  filename      = "build/lambda.zip"
  environment {{
    variables = {{
      LOG_LEVEL = "info"
    }}
  }}
}}''',
        }
    else:
        tf["iam.tf"] = {
            "google_service_account.runtime": f'''resource "google_service_account" "runtime" {{
  account_id   = "{project}"[:28]
  display_name = "{project} runtime"
}}'''.replace('"[:28]', '"'),
            "google_project_iam_member.runtime_logs": f'''resource "google_project_iam_member" "runtime_logs" {{
  project = "{gproj}"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${{google_service_account.runtime.email}}"
}}''',
            "google_project_iam_member.runtime_secrets": f'''resource "google_project_iam_member" "runtime_secrets" {{
  project = "{gproj}"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${{google_service_account.runtime.email}}"
}}''',
            "google_iam_workload_identity_pool_provider.github": f'''resource "google_iam_workload_identity_pool_provider" "github" {{
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "{project}"
  attribute_condition                = "assertion.repository == \\"{org}/{project}\\""
  oidc {{
    issuer_uri = "https://token.actions.githubusercontent.com"
  }}
}}''',
        }
        tf["run.tf"] = {
            "google_cloud_run_v2_service.runtime": f'''resource "google_cloud_run_v2_service" "runtime" {{
  name     = "{project}"
  location = "us-central1"
  template {{
    service_account = google_service_account.runtime.email
    containers {{
      image = "{img}"
    }}
  }}
}}''',
        }

    codeowners = [("/compose.yaml", [f"@{org}/platform"]), ("/deploy/", [f"@{org}/platform"]),
                  ("/infra/", [f"@{org}/infra"]), ("/.env.example", [f"@{org}/{team}"])]
    env_names = ["ANTHROPIC_API_KEY", "SLACK_BOT_TOKEN", "POSTGRES_PASSWORD", "LOG_LEVEL"]
    return {"lang": lang, "project": project, "org": org, "team": team, "cloud": cloud, "ns": ns, "acct": acct,
            "gproj": gproj, "img": img, "compose": compose, "k8s": k8s, "tf": tf, "codeowners": codeowners,
            "env_names": env_names, "extra": {}}


def add_ext_near_misses(spec: dict[str, Any], rng: random.Random) -> None:
    """Legitimate settings that look risky; fixed before any scoring (D-033)."""
    opts = ["empty_default", "secret_file_env", "configmap_env", "deny_star", "var_password", "named_secret_get", "arn_wildcard"]
    for pick in rng.sample(opts, 3):
        if pick == "empty_default":
            spec["compose"]["services"]["agent"]["environment"]["SENTRY_DSN"] = "${SENTRY_DSN:-}"
        elif pick == "secret_file_env":
            spec["compose"]["services"]["worker"]["environment"]["SLACK_SIGNING_SECRET_FILE"] = "/run/secrets/slack_signing"
        elif pick == "configmap_env":
            c = spec["k8s"]["deployment.yaml"][0]["spec"]["template"]["spec"]["containers"][0]
            c["env"].append({"name": "MODEL_NAME", "valueFrom": {"configMapKeyRef": {"name": "agent-config", "key": "model"}}})
        elif pick == "deny_star" and spec["cloud"] == "aws":
            spec["tf"]["deploy.tf"]["data.aws_iam_policy_document.deploy"] = spec["tf"]["deploy.tf"]["data.aws_iam_policy_document.deploy"][:-1] + '''  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}'''
        elif pick == "var_password":
            spec["tf"].setdefault("variables.tf", {})["var.db_password"] = '''variable "db_password" {
  type      = string
  sensitive = true
}'''
        elif pick == "named_secret_get":
            spec["k8s"]["rbac.yaml"][0]["rules"].append(
                {"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["llm-keys"], "verbs": ["get"]})
        elif pick == "arn_wildcard" and spec["cloud"] == "aws":
            pass  # the runtime policy already scopes s3 to bucket/*; nothing to add


def render_ext(spec: dict[str, Any]) -> dict[str, str]:
    t = T[spec["lang"]]
    p = spec["project"]
    files: dict[str, str] = {}
    files["README.md"] = t["readme"].format(p=p, o=spec["org"], team=spec["team"])
    files[".gitignore"] = ".env\nsecrets/\n.terraform/\n*.tfstate*\n"
    files["compose.yaml"] = t["compose_head"].format(p=p) + yaml.dump(
        spec["compose"], Dumper=_Dumper, sort_keys=False, default_flow_style=False, allow_unicode=True, width=200)
    for fname, docs in spec["k8s"].items():
        body = "---\n".join(yaml.dump(d, Dumper=_Dumper, sort_keys=False, default_flow_style=False, allow_unicode=True, width=200)
                            for d in docs)
        files[f"deploy/k8s/{fname}"] = t["k8s_head"].format(p=p, ns=spec["ns"]) + body
    for fname, blocks in spec["tf"].items():
        files[f"infra/{fname}"] = t["tf_head"].format(p=p) + "\n" + "\n\n".join(blocks.values()) + "\n"
    if spec["codeowners"] is not None:
        files[".github/CODEOWNERS"] = t["codeowners"] + "\n" + "".join(f"{pat:<20} {' '.join(o)}".rstrip() + "\n" for pat, o in spec["codeowners"])
    files[".env.example"] = t["env_head"] + "\n" + "".join(f"{n}=\n" if n != "LOG_LEVEL" else "LOG_LEVEL=info\n" for n in spec["env_names"])
    files.update(spec["extra"])
    return files


def clone_ext(spec: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(spec)
