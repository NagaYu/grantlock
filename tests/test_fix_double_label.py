"""Fix round Step 6 (D-045): widening an existing identity to a wildcard/admin grant is labelled G2 *and* G3
on every surface. This was already the semantics (D-013); the test pins it."""

from repo_builder import DEPLOY, MCP, base_repo, of_class, run_check, write
from repo_builder2 import K8S_RBAC, TF, base_repo2


def classes(f):
    return {x["class"] for x in f["findings"]}


def test_mcp_and_gha(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".mcp.json": MCP.replace('"repos"', '"all"')})
    assert {"G2", "G3"} <= classes(run_check(repo))
    write(repo, {".mcp.json": MCP, ".github/workflows/deploy.yml": DEPLOY.replace(
        "    permissions:\n      contents: read\n      id-token: write\n", "    permissions: write-all\n")})
    assert {"G2", "G3"} <= classes(run_check(repo))


def test_k8s_and_terraform(tmp_path):
    repo = base_repo2(tmp_path)
    write(repo, {"deploy/rbac.yaml": K8S_RBAC.replace('verbs: ["get"]', 'verbs: ["*"]')})
    f = run_check(repo)
    assert len(of_class(f, "G2")) == 1 and len(of_class(f, "G3")) == 1
    write(repo, {"deploy/rbac.yaml": K8S_RBAC, "infra/main.tf": TF.replace('Action = ["s3:GetObject"]', 'Action = ["*"]')})
    assert {"G2", "G3"} <= classes(run_check(repo))
