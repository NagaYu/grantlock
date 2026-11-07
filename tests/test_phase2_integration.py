"""Step 4: new surfaces wired into scan(), owners, and G-classes end to end."""

import ast
from pathlib import Path

import grantlock
from grantlock import schemas
from repo_builder import of_class, run_check, write
from repo_builder2 import COMPOSE, K8S_DEPLOY, K8S_RBAC, TF, base_repo2
from secret_guard import assert_no_secret_leak


def classes(f):
    return sorted({x["class"] for x in f["findings"]})


def test_all_new_surfaces_discovered_and_owned(tmp_path):
    repo = base_repo2(tmp_path)
    inv = grantlock.scan(repo)
    kinds = {e["component"]["kind"] for e in inv["entries"]}
    assert {"compose_service", "k8s_workload", "k8s_service_account", "k8s_rbac", "terraform", "terraform_workload"} <= kinds
    for e in inv["entries"]:
        f = e["component"]["file"]
        expected = "@acme/infra" if f.startswith("infra/") else "@acme/platform"
        assert e["owner"]["owners"] == [expected], f
    schemas.validate(inv, schemas.DOC_INVENTORY)


def test_clean_multi_surface_repo_has_no_findings(tmp_path):
    f = run_check(base_repo2(tmp_path))
    assert f["findings"] == []


def test_G1_compose_and_k8s_literals(tmp_path):
    repo = base_repo2(tmp_path)
    leak = "sk-ant-api03-FAKEint0000000000000000000000000000000000000000000000000000000000000000000000000000000000AA"
    write(repo, {"compose.yaml": COMPOSE.replace("${ANTHROPIC_API_KEY}", leak)})
    f = run_check(repo)
    assert classes(f) == ["G1"]
    assert of_class(f, "G1")[0]["component"]["name"] == "agent"
    assert_no_secret_leak(f, [leak])


def test_G2_and_G3_on_k8s_role(tmp_path):
    repo = base_repo2(tmp_path)
    write(repo, {"deploy/rbac.yaml": K8S_RBAC.replace('verbs: ["get"]', 'verbs: ["get", "list", "watch"]')})
    g2 = of_class(run_check(repo), "G2")
    assert [(g["component"]["name"], g["file"]) for g in g2] == [("agent-reader", "deploy/rbac.yaml")]
    write(repo, {"deploy/rbac.yaml": K8S_RBAC.replace('resources: ["configmaps"]', 'resources: ["*"]')})
    f = run_check(repo)
    assert "G3" in classes(f) and of_class(f, "G3")[0]["component"]["name"] == "agent-reader"


def test_G3_terraform_wildcard_policy(tmp_path):
    repo = base_repo2(tmp_path)
    write(repo, {"infra/main.tf": TF.replace('Action = ["s3:GetObject"]', 'Action = ["s3:*"]')})
    f = run_check(repo)
    assert {"G2", "G3"} <= set(classes(f))
    assert {g["component"]["name"] for g in of_class(f, "G3")} == {"aws_iam_role_policy.agent"}


def test_G5_and_G8_terraform_role_consumers(tmp_path):
    repo = base_repo2(tmp_path)
    write(repo, {"infra/main.tf": TF + '\nresource "aws_ecs_task_definition" "agent" {\n  family = "agent"\n  task_role_arn = aws_iam_role.agent.arn\n}\n'})
    g5 = of_class(run_check(repo), "G5")
    assert sorted(g["component"]["name"] for g in g5) == ["aws_ecs_task_definition.agent", "aws_lambda_function.agent"]
    write(repo, {"infra/main.tf": TF.split('resource "aws_lambda_function"')[0]})
    g8 = of_class(run_check(repo), "G8")
    assert [g["component"]["name"] for g in g8] == ["aws_lambda_function.agent"]


def test_G6_k8s_static_cloud_key_secret(tmp_path):
    repo = base_repo2(tmp_path)
    dep = K8S_DEPLOY + """            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef: {name: aws-static, key: AWS_ACCESS_KEY_ID}
"""
    write(repo, {"deploy/deployment.yaml": dep})
    f = run_check(repo)
    assert {g["component"]["name"] for g in of_class(f, "G6")} == {"agent"}
    assert "G7" in classes(f)


def test_G7_new_compose_service_secret(tmp_path):
    repo = base_repo2(tmp_path)
    write(repo, {"compose.yaml": COMPOSE + "  search:\n    image: ghcr.io/acme/search:1\n    environment:\n      TAVILY_API_KEY: ${TAVILY_API_KEY}\n"})
    f = run_check(repo)
    assert classes(f) == ["G7"] and of_class(f, "G7")[0]["component"]["name"] == "search"


def test_G4_on_new_surface(tmp_path):
    repo = base_repo2(tmp_path)
    write(repo, {".github/CODEOWNERS": "/compose.yaml @acme/platform\n/deploy/ @acme/platform\n"})
    g4 = of_class(run_check(repo), "G4")
    assert g4 and {g["file"] for g in g4} == {"infra/main.tf"}


def test_G8_k8s_service_account_no_longer_used(tmp_path):
    repo = base_repo2(tmp_path)
    write(repo, {"deploy/deployment.yaml": K8S_DEPLOY.replace("      serviceAccountName: agent\n", "")})
    g8 = of_class(run_check(repo), "G8")
    assert [(g["identity_id"], g["component"]["name"]) for g in g8] == [("kubernetes:serviceaccount:agents/agent", "agent")]


def test_ast_network_check_covers_new_modules():
    core = Path(__file__).parents[1] / "grantlock"
    names = {p.relative_to(core).as_posix() for p in core.rglob("*.py")}
    assert {"parsers/compose.py", "parsers/k8s.py", "parsers/terraform.py"} <= names
    forbidden = {"socket", "ssl", "http", "urllib.request", "requests", "httpx", "aiohttp", "subprocess"}
    for name in ("parsers/compose.py", "parsers/k8s.py", "parsers/terraform.py"):
        tree = ast.parse((core / name).read_text())
        mods = [a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names]
        mods += [n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module and n.level == 0]
        assert not [m for m in mods if m in forbidden or m.split(".")[0] in forbidden], name


def test_G2_new_grant_component_for_existing_identity(tmp_path):
    """D-031: a new RBAC binding / IAM member for an identity already in the lock is a permission addition."""
    repo = base_repo2(tmp_path)
    extra = """---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: agent-secrets
  namespace: agents
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: agent-secrets
  namespace: agents
subjects:
  - kind: ServiceAccount
    name: agent
    namespace: agents
roleRef:
  kind: Role
  name: agent-secrets
  apiGroup: rbac.authorization.k8s.io
"""
    write(repo, {"deploy/rbac.yaml": K8S_RBAC + extra})
    f = run_check(repo)
    g2 = of_class(f, "G2")
    assert [(g["component"]["name"], g["details"]["added_scopes"]) for g in g2] == [("agent-secrets", ["rbac:ns:get:secrets"])]
    assert "G7" not in classes(f)


def test_new_binding_without_new_scopes_is_not_G2(tmp_path):
    repo = base_repo2(tmp_path)
    dup = K8S_RBAC.replace("name: agent-reader\n  namespace: agents\nrules", "name: agent-reader-2\n  namespace: agents\nrules").replace(
        "kind: RoleBinding\nmetadata:\n  name: agent-reader", "kind: RoleBinding\nmetadata:\n  name: agent-reader-2").replace(
        "kind: Role\n  name: agent-reader\n", "kind: Role\n  name: agent-reader-2\n")
    write(repo, {"deploy/rbac2.yaml": dup})
    assert of_class(run_check(repo), "G2") == []
