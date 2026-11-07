"""dev-ext risk mutations on the compose / Kubernetes / Terraform surfaces.

Each variant edits a spec in place and returns its planted list. Every variant
declares its surface and (optionally) a cloud requirement. Labels for diff
pairs are derived from SPEC.md / DECISIONS.md semantics by hand.
"""

from __future__ import annotations

import base64
import copy
from typing import Callable

from .ext_templates import real_fake

COMPOSE = "compose.yaml"


def _p(cls, file, component, note):
    return {"class": cls, "file": file, "component": component, "note": note}


def variant(surface: str, *req: str):
    def deco(fn):
        fn.surface = surface
        fn.requires = set(req)
        return fn
    return deco


def _k(spec, fname):
    return f"deploy/k8s/{fname}"


def _dep(spec):
    return spec["k8s"]["deployment.yaml"][0]


def _container(spec):
    return _dep(spec)["spec"]["template"]["spec"]["containers"][0]


def _role(spec):
    return spec["k8s"]["rbac.yaml"][0]


def _tf_add(spec, fname, addr, text):
    spec["tf"].setdefault(fname, {})[addr] = text


def _tf_file_of(spec, addr):
    return next(f for f, blocks in spec["tf"].items() if addr in blocks)


def _rb(name, ns, sa, role_kind, role, cluster=False):
    md = {"name": name} if cluster else {"name": name, "namespace": ns}
    return {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding" if cluster else "RoleBinding",
            "metadata": md, "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": ns}],
            "roleRef": {"kind": role_kind, "name": role, "apiGroup": "rbac.authorization.k8s.io"}}


# ============================================================================ G1

@variant("compose")
def c_env_literal(spec, rng, sink):
    spec["compose"]["services"]["agent"]["environment"]["ANTHROPIC_API_KEY"] = sink(real_fake(rng, "anthropic"))
    return [_p("G1", COMPOSE, "agent", "API key pasted into service environment")]


@variant("compose")
def c_dburl_literal(spec, rng, sink):
    env = spec["compose"]["services"]["agent"]["environment"]
    env["DATABASE_URL"] = env["DATABASE_URL"].replace("${POSTGRES_PASSWORD}", sink(real_fake(rng, "password")))
    return [_p("G1", COMPOSE, "agent", "password embedded in DATABASE_URL")]


@variant("k8s")
def k_env_literal(spec, rng, sink):
    env = _container(spec)["env"]
    for e in env:
        if e["name"] == "SLACK_BOT_TOKEN":
            e.pop("valueFrom")
            e["value"] = sink(real_fake(rng, "slack"))
    return [_p("G1", _k(spec, "deployment.yaml"), spec["project"], "bot token as literal env value")]


@variant("k8s")
def k_secret_data(spec, rng, sink):
    kid, sec = sink(real_fake(rng, "aws_id")), sink(real_fake(rng, "aws_secret"))
    spec["k8s"]["secrets.yaml"] = [{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                                     "metadata": {"name": "export-creds", "namespace": spec["ns"]},
                                     "data": {"AWS_ACCESS_KEY_ID": base64.b64encode(kid.encode()).decode(),
                                              "AWS_SECRET_ACCESS_KEY": base64.b64encode(sec.encode()).decode()}}]
    return [_p("G1", _k(spec, "secrets.yaml"), "export-creds", "Secret manifest with committed data values")]


@variant("terraform", "aws")
def t_provider_keys(spec, rng, sink):
    _tf_add(spec, "providers.tf", "provider.aws", f'''provider "aws" {{
  region     = "us-east-1"
  access_key = "{sink(real_fake(rng, 'aws_id'))}"
  secret_key = "{sink(real_fake(rng, 'aws_secret'))}"
}}''')
    return [_p("G1", "infra/providers.tf", "provider.aws", "static keys written into provider block")]


@variant("terraform")
def t_var_default(spec, rng, sink):
    _tf_add(spec, "variables.tf", "var.openai_api_key", f'''variable "openai_api_key" {{
  type      = string
  sensitive = true
  default   = "{sink(real_fake(rng, 'openai'))}"
}}''')
    return [_p("G1", "infra/variables.tf", "var.openai_api_key", "secret as variable default")]


# ============================================================================ G2

@variant("k8s")
def k_role_verbs(spec, rng, sink):
    _role(spec)["rules"][0]["verbs"] = ["get", "list", "watch", "update"]
    return [_p("G2", _k(spec, "rbac.yaml"), f"{spec['project']}-reader", "watch/update added to configmaps rule")]


@variant("k8s")
def k_role_exec(spec, rng, sink):
    _role(spec)["rules"].append({"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]})
    return [_p("G2", _k(spec, "rbac.yaml"), f"{spec['project']}-reader", "pods/exec create added")]


@variant("k8s")
def k_new_binding(spec, rng, sink):
    ns, p = spec["ns"], spec["project"]
    spec["k8s"]["rbac.yaml"] += [
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": f"{p}-jobs", "namespace": ns},
         "rules": [{"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["create", "delete"]}]},
        _rb(f"{p}-jobs", ns, p, "Role", f"{p}-jobs")]
    return [_p("G2", _k(spec, "rbac.yaml"), f"{p}-jobs", "new Role bound to the existing service account")]


@variant("terraform", "aws")
def t_doc_action(spec, rng, sink):
    b = spec["tf"]["deploy.tf"]["data.aws_iam_policy_document.deploy"]
    spec["tf"]["deploy.tf"]["data.aws_iam_policy_document.deploy"] = b.replace(
        '"ecs:DescribeServices"]', '"ecs:DescribeServices", "ecs:RegisterTaskDefinition", "iam:PassRole"]', 1)
    return [_p("G2", "infra/deploy.tf", "data.aws_iam_policy_document.deploy", "deploy role gains PassRole")]


@variant("terraform", "aws")
def t_role_policy_action(spec, rng, sink):
    b = spec["tf"]["runtime.tf"]["aws_iam_role_policy.runtime"]
    spec["tf"]["runtime.tf"]["aws_iam_role_policy.runtime"] = b.replace('Action = ["s3:GetObject"]', 'Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]')
    return [_p("G2", "infra/runtime.tf", "aws_iam_role_policy.runtime", "runtime role gains write/delete")]


@variant("terraform", "gcp")
def t_gcp_new_member(spec, rng, sink):
    spec["tf"]["iam.tf"]["google_project_iam_member.runtime_storage"] = f'''resource "google_project_iam_member" "runtime_storage" {{
  project = "{spec['gproj']}"
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${{google_service_account.runtime.email}}"
}}'''
    return [_p("G2", "infra/iam.tf", "google_project_iam_member.runtime_storage", "storage.objectAdmin granted to runtime SA")]


# ============================================================================ G3

@variant("k8s")
def k_role_star(spec, rng, sink):
    _role(spec)["rules"][0]["verbs"] = ["*"]
    return [_p("G3", _k(spec, "rbac.yaml"), f"{spec['project']}-reader", "verbs '*' on configmaps rule")]


@variant("k8s")
def k_bind_cluster_admin(spec, rng, sink):
    spec["k8s"]["rbac.yaml"].append(_rb(f"{spec['project']}-admin", spec["ns"], spec["project"], "ClusterRole", "cluster-admin", cluster=True))
    return [_p("G3", _k(spec, "rbac.yaml"), f"{spec['project']}-admin", "service account bound to cluster-admin")]


@variant("k8s")
def k_cluster_secret_reader(spec, rng, sink):
    p = spec["project"]
    spec["k8s"]["rbac.yaml"] += [
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": f"{p}-secret-reader"},
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list", "watch"]}]},
        _rb(f"{p}-secret-reader", spec["ns"], p, "ClusterRole", f"{p}-secret-reader", cluster=True)]
    return [_p("G3", _k(spec, "rbac.yaml"), f"{p}-secret-reader", "cluster-wide read on all secrets")]


@variant("terraform", "aws")
def t_star_policy(spec, rng, sink):
    b = spec["tf"]["runtime.tf"]["aws_iam_role_policy.runtime"]
    spec["tf"]["runtime.tf"]["aws_iam_role_policy.runtime"] = b.replace(
        'Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::', 'Action = ["*"], Resource = ["*"] }, { Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::')
    return [_p("G3", "infra/runtime.tf", "aws_iam_role_policy.runtime", "Action * / Resource * statement")]


@variant("terraform", "aws")
def t_admin_attach(spec, rng, sink):
    spec["tf"]["runtime.tf"]["aws_iam_role_policy_attachment.runtime_admin"] = '''resource "aws_iam_role_policy_attachment" "runtime_admin" {
  role       = aws_iam_role.runtime.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}'''
    return [_p("G3", "infra/runtime.tf", "aws_iam_role_policy_attachment.runtime_admin", "AdministratorAccess attached")]


@variant("terraform", "gcp")
def t_gcp_editor(spec, rng, sink):
    spec["tf"]["iam.tf"]["google_project_iam_member.runtime_editor"] = f'''resource "google_project_iam_member" "runtime_editor" {{
  project = "{spec['gproj']}"
  role    = "roles/editor"
  member  = "serviceAccount:${{google_service_account.runtime.email}}"
}}'''
    return [_p("G3", "infra/iam.tf", "google_project_iam_member.runtime_editor", "roles/editor on the project")]


# ============================================================================ G4

@variant("compose")
def c_drop_rule(spec, rng, sink):
    spec["codeowners"] = [r for r in spec["codeowners"] if r[0] != "/compose.yaml"]
    return [_p("G4", COMPOSE, "agent", "CODEOWNERS rule for compose.yaml removed")]


@variant("compose")
def c_explicit_unowned(spec, rng, sink):
    spec["codeowners"].append(("/compose.yaml", []))
    return [_p("G4", COMPOSE, "worker", "trailing ownerless rule for compose.yaml")]


@variant("k8s")
def k_narrow_rule(spec, rng, sink):
    owners = next(o for p, o in spec["codeowners"] if p == "/deploy/")
    spec["codeowners"] = [r for r in spec["codeowners"] if r[0] != "/deploy/"] + [("/deploy/k8s/rbac.yaml", owners)]
    return [_p("G4", _k(spec, "deployment.yaml"), spec["project"], "deploy/ rule narrowed to rbac.yaml")]


@variant("k8s")
def k_typo(spec, rng, sink):
    spec["codeowners"] = [("/deplyo/", o) if p == "/deploy/" else (p, o) for p, o in spec["codeowners"]]
    return [_p("G4", _k(spec, "serviceaccount.yaml"), spec["project"], "typo in CODEOWNERS path")]


@variant("terraform")
def t_drop_rule(spec, rng, sink):
    spec["codeowners"] = [r for r in spec["codeowners"] if r[0] != "/infra/"]
    comp = "aws_lambda_function.runtime" if spec["cloud"] == "aws" else "google_cloud_run_v2_service.runtime"
    return [_p("G4", "infra/runtime.tf" if spec["cloud"] == "aws" else "infra/run.tf", comp, "CODEOWNERS rule for infra/ removed")]


@variant("terraform")
def t_unowned_file(spec, rng, sink):
    f = "runtime.tf" if spec["cloud"] == "aws" else "iam.tf"
    spec["codeowners"].append((f"/infra/{f}", []))
    comp = "aws_iam_role.runtime" if spec["cloud"] == "aws" else "google_service_account.runtime"
    return [_p("G4", f"infra/{f}", comp, "explicit ownerless rule for an IAM file")]


# ============================================================================ G5

@variant("compose")
def c_worker_reuses_key(spec, rng, sink):
    spec["compose"]["services"]["worker"]["environment"]["ANTHROPIC_API_KEY"] = "${ANTHROPIC_API_KEY}"
    return [_p("G5", COMPOSE, "worker", "worker reuses the agent's API key"), _p("G5", COMPOSE, "agent", "key now shared")]


@variant("compose")
def c_shared_env_file(spec, rng, sink):
    for s in ("agent", "worker"):
        spec["compose"]["services"][s]["env_file"] = ["./config/runtime.env"]
    return [_p("G5", COMPOSE, "agent", "shared env_file"), _p("G5", COMPOSE, "worker", "shared env_file")]


@variant("k8s")
def k_cronjob_same_sa(spec, rng, sink):
    p, ns = spec["project"], spec["ns"]
    spec["k8s"]["cronjob.yaml"] = [{"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": f"{p}-digest", "namespace": ns},
                                     "spec": {"schedule": "0 6 * * 1-5", "jobTemplate": {"spec": {"template": {"spec": {
                                         "serviceAccountName": p, "restartPolicy": "OnFailure",
                                         "containers": [{"name": "digest", "image": spec["img"], "args": ["digest"]}]}}}}}}]
    return [_p("G5", _k(spec, "cronjob.yaml"), f"{p}-digest", "cronjob runs as the agent's service account"),
            _p("G5", _k(spec, "deployment.yaml"), p, "service account now shared")]


@variant("k8s")
def k_second_deploy_same_secret(spec, rng, sink):
    p, ns = spec["project"], spec["ns"]
    d = copy.deepcopy(_dep(spec))
    d["metadata"]["name"] = f"{p}-canary"
    d["spec"]["replicas"] = 1
    d["spec"]["template"]["spec"].pop("serviceAccountName")
    d["spec"]["template"]["spec"]["containers"][0]["env"] = [e for e in d["spec"]["template"]["spec"]["containers"][0]["env"] if e["name"] == "ANTHROPIC_API_KEY"]
    spec["k8s"]["deployment.yaml"].append(d)
    return [_p("G5", _k(spec, "deployment.yaml"), f"{p}-canary", "canary reads the same API key"),
            _p("G5", _k(spec, "deployment.yaml"), p, "key now shared")]


@variant("terraform", "aws")
def t_ecs_same_role(spec, rng, sink):
    spec["tf"]["runtime.tf"]["aws_ecs_task_definition.runtime"] = f'''resource "aws_ecs_task_definition" "runtime" {{
  family                = "{spec['project']}"
  task_role_arn         = aws_iam_role.runtime.arn
  container_definitions = jsonencode([{{ name = "agent", image = "{spec['img']}" }}])
}}'''
    return [_p("G5", "infra/runtime.tf", "aws_ecs_task_definition.runtime", "ECS task reuses the lambda role"),
            _p("G5", "infra/runtime.tf", "aws_lambda_function.runtime", "role now shared")]


@variant("terraform", "gcp")
def t_second_run_same_sa(spec, rng, sink):
    spec["tf"]["run.tf"]["google_cloud_run_v2_service.admin_ui"] = f'''resource "google_cloud_run_v2_service" "admin_ui" {{
  name     = "{spec['project']}-admin"
  location = "us-central1"
  template {{
    service_account = google_service_account.runtime.email
    containers {{
      image = "{spec['img']}"
    }}
  }}
}}'''
    return [_p("G5", "infra/run.tf", "google_cloud_run_v2_service.admin_ui", "second service runs as the same SA"),
            _p("G5", "infra/run.tf", "google_cloud_run_v2_service.runtime", "SA now shared")]


# ============================================================================ G6

@variant("compose")
def c_aws_static(spec, rng, sink):
    spec["compose"]["services"]["worker"]["environment"].update(
        {"AWS_ACCESS_KEY_ID": "${AWS_ACCESS_KEY_ID}", "AWS_SECRET_ACCESS_KEY": "${AWS_SECRET_ACCESS_KEY}", "AWS_REGION": "us-east-1"})
    return [_p("G6", COMPOSE, "worker", "static IAM user keys for the worker")]


@variant("compose")
def c_gcp_keyfile(spec, rng, sink):
    spec["compose"]["services"]["agent"]["environment"]["GOOGLE_APPLICATION_CREDENTIALS"] = "/run/secrets/gcp-sa.json"
    spec["compose"]["services"]["agent"].setdefault("volumes", []).append("./secrets/gcp-sa.json:/run/secrets/gcp-sa.json:ro")
    return [_p("G6", COMPOSE, "agent", "service-account key file mounted")]


@variant("k8s")
def k_static_secret_ref(spec, rng, sink):
    _container(spec)["env"] += [
        {"name": "AWS_ACCESS_KEY_ID", "valueFrom": {"secretKeyRef": {"name": "aws-static", "key": "AWS_ACCESS_KEY_ID"}}},
        {"name": "AWS_SECRET_ACCESS_KEY", "valueFrom": {"secretKeyRef": {"name": "aws-static", "key": "AWS_SECRET_ACCESS_KEY"}}}]
    return [_p("G6", _k(spec, "deployment.yaml"), spec["project"], "static AWS keys although IRSA/WI is available")]


@variant("k8s")
def k_legacy_sa_token(spec, rng, sink):
    spec["k8s"]["serviceaccount.yaml"].append(
        {"apiVersion": "v1", "kind": "Secret", "type": "kubernetes.io/service-account-token",
         "metadata": {"name": f"{spec['project']}-token", "namespace": spec["ns"],
                      "annotations": {"kubernetes.io/service-account.name": spec["project"]}}})
    return [_p("G6", _k(spec, "serviceaccount.yaml"), f"{spec['project']}-token", "legacy long-lived SA token secret")]


@variant("terraform", "aws")
def t_access_key(spec, rng, sink):
    spec["tf"]["ci.tf"] = {
        "aws_iam_user.ci": '''resource "aws_iam_user" "ci" {
  name = "ci-deployer"
}''',
        "aws_iam_access_key.ci": '''resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}'''}
    return [_p("G6", "infra/ci.tf", "aws_iam_access_key.ci", "IAM user access key although OIDC provider exists")]


@variant("terraform", "gcp")
def t_sa_key(spec, rng, sink):
    spec["tf"]["iam.tf"]["google_service_account_key.runtime"] = '''resource "google_service_account_key" "runtime" {
  service_account_id = google_service_account.runtime.name
}'''
    return [_p("G6", "infra/iam.tf", "google_service_account_key.runtime", "long-lived SA key although WIF exists")]


# ============================================================================ G7

@variant("compose")
def c_new_service(spec, rng, sink):
    spec["compose"]["services"]["search"] = {"image": "ghcr.io/acme/search-mcp:0.3",
                                             "environment": {"TAVILY_API_KEY": "${TAVILY_API_KEY}", "PORT": "9000"}}
    return [_p("G7", COMPOSE, "search", "new service with a new credential")]


@variant("compose")
def c_new_env_cred(spec, rng, sink):
    spec["compose"]["services"]["worker"]["environment"]["LINEAR_API_KEY"] = "${LINEAR_API_KEY}"
    return [_p("G7", COMPOSE, "worker", "new credential for an existing service")]


@variant("k8s")
def k_new_secret_ref(spec, rng, sink):
    _container(spec)["env"].append({"name": "OPENAI_API_KEY", "valueFrom": {"secretKeyRef": {"name": "llm-keys", "key": "OPENAI_API_KEY"}}})
    return [_p("G7", _k(spec, "deployment.yaml"), spec["project"], "new secret key consumed")]


@variant("k8s")
def k_new_sa_cronjob(spec, rng, sink):
    p, ns = spec["project"], spec["ns"]
    spec["k8s"]["reindex.yaml"] = [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": f"{p}-reindex", "namespace": ns}},
        {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": {"name": f"{p}-reindex", "namespace": ns},
         "spec": {"schedule": "30 2 * * *", "jobTemplate": {"spec": {"template": {"spec": {
             "serviceAccountName": f"{p}-reindex", "restartPolicy": "OnFailure",
             "containers": [{"name": "reindex", "image": spec["img"], "args": ["reindex"]}]}}}}}}]
    return [_p("G7", _k(spec, "reindex.yaml"), f"{p}-reindex", "new service account and job")]


@variant("terraform", "aws")
def t_new_role_lambda(spec, rng, sink):
    p = spec["project"]
    spec["tf"]["ingest.tf"] = {
        "aws_iam_role.ingest": f'''resource "aws_iam_role" "ingest" {{
  name = "{p}-ingest"
  assume_role_policy = jsonencode({{ Statement = [{{ Effect = "Allow", Principal = {{ Service = "lambda.amazonaws.com" }}, Action = "sts:AssumeRole" }}] }})
}}''',
        "aws_lambda_function.ingest": f'''resource "aws_lambda_function" "ingest" {{
  function_name = "{p}-ingest"
  role          = aws_iam_role.ingest.arn
  runtime       = "python3.12"
  handler       = "ingest.handler"
}}'''}
    return [_p("G7", "infra/ingest.tf", "aws_lambda_function.ingest", "new role + function")]


@variant("terraform", "gcp")
def t_new_gcp_sa(spec, rng, sink):
    spec["tf"]["iam.tf"]["google_service_account.exporter"] = '''resource "google_service_account" "exporter" {
  account_id = "exporter"
}'''
    return [_p("G7", "infra/iam.tf", "google_service_account.exporter", "new service account")]


# ============================================================================ G8

@variant("compose")
def c_drop_env(spec, rng, sink):
    del spec["compose"]["services"]["worker"]["environment"]["SLACK_BOT_TOKEN"]
    return [_p("G8", COMPOSE, "worker", "worker no longer uses the bot token")]


@variant("compose")
def c_drop_service(spec, rng, sink):
    del spec["compose"]["services"]["worker"]
    return [_p("G8", COMPOSE, "worker", "worker service removed")]


@variant("k8s")
def k_drop_sa(spec, rng, sink):
    _dep(spec)["spec"]["template"]["spec"].pop("serviceAccountName")
    return [_p("G8", _k(spec, "deployment.yaml"), spec["project"], "deployment stops using the federated SA")]


@variant("k8s")
def k_drop_secret_ref(spec, rng, sink):
    c = _container(spec)
    c["env"] = [e for e in c["env"] if e["name"] != "SLACK_BOT_TOKEN"]
    return [_p("G8", _k(spec, "deployment.yaml"), spec["project"], "slack token no longer consumed")]


@variant("terraform", "aws")
def t_drop_lambda(spec, rng, sink):
    del spec["tf"]["runtime.tf"]["aws_lambda_function.runtime"]
    return [_p("G8", "infra/runtime.tf", "aws_lambda_function.runtime", "function removed; role remains")]


@variant("terraform", "gcp")
def t_drop_run(spec, rng, sink):
    del spec["tf"]["run.tf"]["google_cloud_run_v2_service.runtime"]
    return [_p("G8", "infra/run.tf", "google_cloud_run_v2_service.runtime", "service removed; SA remains")]


EXT_PLANTED: dict[str, list[Callable]] = {
    "G1": [c_env_literal, c_dburl_literal, k_env_literal, k_secret_data, t_provider_keys, t_var_default],
    "G2": [k_role_verbs, k_role_exec, k_new_binding, t_doc_action, t_role_policy_action, t_gcp_new_member],
    "G3": [k_role_star, k_bind_cluster_admin, k_cluster_secret_reader, t_star_policy, t_admin_attach, t_gcp_editor],
    "G4": [c_drop_rule, c_explicit_unowned, k_narrow_rule, k_typo, t_drop_rule, t_unowned_file],
    "G5": [c_worker_reuses_key, c_shared_env_file, k_cronjob_same_sa, k_second_deploy_same_secret, t_ecs_same_role, t_second_run_same_sa],
    "G6": [c_aws_static, c_gcp_keyfile, k_static_secret_ref, k_legacy_sa_token, t_access_key, t_sa_key],
    "G7": [c_new_service, c_new_env_cred, k_new_secret_ref, k_new_sa_cronjob, t_new_role_lambda, t_new_gcp_sa],
    "G8": [c_drop_env, c_drop_service, k_drop_sa, k_drop_secret_ref, t_drop_lambda, t_drop_run],
}


# ============================================================================ diff pairs

@variant("compose")
def d_rename_service(spec, rng, sink):
    svcs = spec["compose"]["services"]
    spec["compose"]["services"] = {("jobs" if k == "worker" else k): v for k, v in svcs.items()}
    return []


@variant("k8s")
def d_role_reduce(spec, rng, sink):
    _role(spec)["rules"][0]["verbs"] = ["get"]
    return []


@variant("terraform")
def d_tags(spec, rng, sink):
    f = "runtime.tf" if spec["cloud"] == "aws" else "run.tf"
    addr = "aws_lambda_function.runtime" if spec["cloud"] == "aws" else "google_cloud_run_v2_service.runtime"
    b = spec["tf"][f][addr]
    spec["tf"][f][addr] = b[:-1] + '  # owned by the agents team\n  labels_note = "cost-center-42"\n}'
    return []


@variant("terraform")
def d_drop_consumer(spec, rng, sink):
    return t_drop_lambda(spec, rng, sink) if spec["cloud"] == "aws" else t_drop_run(spec, rng, sink)


EXT_DIFF_PAIRS: list[tuple[Callable, list[str]]] = [
    (d_rename_service, []),
    (d_role_reduce, []),
    (d_tags, []),
    (k_role_star, ["G2", "G3"]),
    (t_access_key, ["G6", "G7"]),
    (c_env_literal, ["G1"]),
    (d_drop_consumer, ["G8"]),
    (k_cronjob_same_sa, ["G5"]),
]
