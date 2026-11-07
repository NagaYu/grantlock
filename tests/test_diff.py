"""One dedicated test group per class G1-G8, plus severity policy and invariants."""

import hashlib
import json
import os

import pytest

import grantlock
from grantlock import lockfile, schemas
from grantlock.check import MissingLockfile, check
from grantlock.policy import PolicyError, default_policy, merge_policy
from repo_builder import DEPLOY, MCP, base_repo, of_class, relock, run_check, write
from secret_guard import assert_no_secret_leak


def classes(f):
    return sorted({x["class"] for x in f["findings"]})


def test_clean_base_has_no_findings(tmp_path):
    repo = base_repo(tmp_path)
    f = run_check(repo)
    assert f["findings"] == [] and f["drift"] == []
    assert f["summary"]["exit_code"] == 0 and f["summary"]["lock_in_sync"] is True
    schemas.validate(f, schemas.DOC_FINDINGS)


# ---------------------------------------------------------------- G1 -------

def test_G1_inline_secret_introduced(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".mcp.json": MCP.replace('"${GITHUB_PERSONAL_ACCESS_TOKEN}"', '"ghp_FAKEleak000000000000000000000000000"')})
    f = run_check(repo)
    assert classes(f) == ["G1"]
    g1 = of_class(f, "G1")[0]
    assert g1["change"] == "introduced" and g1["severity"] == "warning"
    assert g1["details"]["format"] == {"class": "github_pat_classic", "prefix": "ghp_"}
    assert g1["details"]["previous_storage"] == "env"
    assert g1["file"] == ".mcp.json" and g1["line"] == 7
    assert_no_secret_leak(f)


def test_G1_placeholder_is_not_inline(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".mcp.json": MCP.replace('"${GITHUB_PERSONAL_ACCESS_TOKEN}"', '"<your-github-pat>"')})
    assert of_class(run_check(repo), "G1") == []


def test_G1_already_locked_is_unchanged(tmp_path):
    repo = base_repo(tmp_path, {".mcp.json": MCP.replace('"${GITHUB_PERSONAL_ACCESS_TOKEN}"', '"ghp_FAKEleak000000000000000000000000000"')})
    g1 = of_class(run_check(repo), "G1")
    assert len(g1) == 1 and g1[0]["change"] == "unchanged"


# ---------------------------------------------------------------- G2 -------

def test_G2_scope_added_on_production_is_critical(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace(
        "      id-token: write\n", "      id-token: write\n      pull-requests: write\n")})
    f = run_check(repo)
    assert classes(f) == ["G2"]
    g2 = of_class(f, "G2")[0]
    assert g2["details"]["added_scopes"] == ["pull-requests:write"]
    assert g2["severity"] == "critical" and g2["production"]["value"] is True
    assert any("environment 'production'" in x for x in g2["production"]["evidence"])
    assert f["summary"]["exit_code"] == 1


def test_G2_non_production_is_warning(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace(
        "    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@v4\n      - run: make test",
        "    permissions:\n      contents: write\n    steps:\n      - uses: actions/checkout@v4\n      - run: make test")})
    f = run_check(repo)
    g2 = of_class(f, "G2")
    assert len(g2) == 1 and g2[0]["details"]["added_scopes"] == ["contents:write"]
    assert g2[0]["severity"] == "warning" and f["summary"]["exit_code"] == 0


def test_G2_permissions_removed_to_implicit_default(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace("permissions:\n  contents: read\njobs:", "jobs:").replace(
        "    permissions:\n      contents: read\n    steps:\n      - uses: actions/checkout@v4\n      - run: make test",
        "    steps:\n      - uses: actions/checkout@v4\n      - run: make test")})
    g2 = of_class(run_check(repo), "G2")
    assert len(g2) == 1
    assert g2[0]["details"]["scope_source_change"] == ["explicit", "implicit_default"]


def test_G2_mcp_toolset_added(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".mcp.json": MCP.replace('"repos"', '"repos,pull_requests"')})
    g2 = of_class(run_check(repo), "G2")
    assert [g["details"]["added_scopes"] for g in g2] == [["toolset:pull_requests"]]


def test_G2_scope_reduction_is_drift_not_finding(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace("      id-token: write\n", "")})
    f = run_check(repo)
    assert of_class(f, "G2") == []
    assert any(d["kind"] == "scopes_removed" for d in f["drift"])
    assert f["summary"]["lock_in_sync"] is False


# ---------------------------------------------------------------- G3 -------

def test_G3_write_all_on_production_is_critical(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace(
        "    permissions:\n      contents: read\n      id-token: write\n", "    permissions: write-all\n")})
    f = run_check(repo)
    g3 = of_class(f, "G3")
    assert len(g3) == 1 and g3[0]["severity"] == "critical"
    assert g3[0]["details"]["wildcard_reasons"] == ["permissions: write-all"]
    assert "G2" in classes(f)


def test_G3_mcp_toolset_all(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".mcp.json": MCP.replace('"repos"', '"all"')})
    g3 = of_class(run_check(repo), "G3")
    assert len(g3) == 1 and "toolset:*" in g3[0]["details"]["wildcard_reasons"][0]
    assert g3[0]["severity"] == "warning"


def test_G3_admin_role_name(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace("role/gha-deploy", "role/AdministratorAccess")})
    f = run_check(repo)
    g3 = of_class(f, "G3")
    assert len(g3) == 1 and g3[0]["severity"] == "critical"
    assert "G7" in classes(f) and "G8" in classes(f)  # a different role is a different identity


def test_G3_already_locked_is_capped_at_warning(tmp_path):
    prod_write_all = DEPLOY.replace("    permissions:\n      contents: read\n      id-token: write\n", "    permissions: write-all\n")
    repo = base_repo(tmp_path, {".github/workflows/deploy.yml": prod_write_all})
    f = run_check(repo)
    g3 = of_class(f, "G3")
    assert len(g3) == 1 and g3[0]["change"] == "unchanged" and g3[0]["severity"] == "warning"
    assert f["summary"]["exit_code"] == 0


# ---------------------------------------------------------------- G4 -------

def test_G4_codeowners_removed(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/CODEOWNERS": None})
    f = run_check(repo)
    g4 = of_class(f, "G4")
    assert len(g4) == len(grantlock.scan(repo)["entries"])
    assert all(g["change"] == "introduced" and g["severity"] == "warning" for g in g4)
    assert classes(f) == ["G4"]


def test_G4_partial_coverage(tmp_path):
    repo = base_repo(tmp_path, {".github/CODEOWNERS": "/.github/  @acme/platform\n/.env.example @acme/ai\n"})
    g4 = of_class(run_check(repo), "G4")
    assert {g["file"] for g in g4} == {".mcp.json"}
    assert all(g["change"] == "unchanged" for g in g4)


# ---------------------------------------------------------------- G5 -------

def test_G5_identity_shared_by_two_servers(tmp_path):
    repo = base_repo(tmp_path)
    shared = json.loads(MCP)
    shared["mcpServers"]["triage"] = {"command": "npx", "args": ["-y", "@acme/triage-mcp"],
                                      "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"}}
    write(repo, {".mcp.json": json.dumps(shared, indent=2)})
    f = run_check(repo)
    g5 = of_class(f, "G5")
    assert sorted(g["component"]["name"] for g in g5) == ["github", "triage"]
    assert all(g["details"]["shared_with"] for g in g5)
    assert classes(f) == ["G5"]
    assert any(d["kind"] == "binding_added" for d in f["drift"])


def test_G5_declaration_does_not_count_as_sharing(tmp_path):
    repo = base_repo(tmp_path)  # .env.example declares the PAT that one server uses
    assert of_class(run_check(repo), "G5") == []


def test_G5_secret_shared_across_jobs(tmp_path):
    repo = base_repo(tmp_path)
    wf = DEPLOY.replace("      - run: make test", "      - run: make test\n        env:\n          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}")
    wf = wf.replace("      - run: ./deploy.sh", "      - run: ./deploy.sh\n        env:\n          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}")
    write(repo, {".github/workflows/deploy.yml": wf})
    g5 = of_class(run_check(repo), "G5")
    assert sorted(g["component"]["name"] for g in g5) == ["Deploy/deploy", "Deploy/test"]


# ---------------------------------------------------------------- G6 -------

def test_G6_static_aws_key_in_workflow(tmp_path):
    repo = base_repo(tmp_path)
    wf = DEPLOY.replace(
        "          role-to-assume: arn:aws:iam::123456789012:role/gha-deploy\n",
        "          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}\n          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n")
    write(repo, {".github/workflows/deploy.yml": wf})
    f = run_check(repo)
    g6 = of_class(f, "G6")
    assert len(g6) == 1 and g6[0]["identity_id"] == "aws:AWS_ACCESS_KEY_ID"
    assert "OIDC" in g6[0]["details"]["federation_reason"]
    assert set(classes(f)) == {"G6", "G7", "G8"}


def test_G6_static_cloud_key_in_mcp(tmp_path):
    repo = base_repo(tmp_path)
    m = json.loads(MCP)
    m["mcpServers"]["aws"] = {"command": "uvx", "args": ["awslabs.aws-api-mcp-server"],
                              "env": {"AWS_ACCESS_KEY_ID": "${AWS_ACCESS_KEY_ID}", "AWS_SECRET_ACCESS_KEY": "${AWS_SECRET_ACCESS_KEY}"}}
    write(repo, {".mcp.json": json.dumps(m, indent=2)})
    g6 = of_class(run_check(repo), "G6")
    assert len(g6) == 1 and "SSO" in g6[0]["details"]["federation_reason"]


def test_G6_not_raised_for_federated_or_non_federatable(tmp_path):
    repo = base_repo(tmp_path)
    assert of_class(run_check(repo), "G6") == []
    m = json.loads(MCP)
    m["mcpServers"]["notion"] = {"command": "npx", "args": ["-y", "@notionhq/notion-mcp-server"],
                                 "env": {"NOTION_TOKEN": "${NOTION_TOKEN}"}}
    write(repo, {".mcp.json": json.dumps(m, indent=2)})
    assert of_class(run_check(repo), "G6") == []


# ---------------------------------------------------------------- G7 -------

def test_G7_new_secret_in_production_job_is_critical(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace(
        "      - run: ./deploy.sh", "      - run: ./deploy.sh\n        env:\n          DATADOG_API_KEY: ${{ secrets.DATADOG_API_KEY }}")})
    f = run_check(repo)
    assert classes(f) == ["G7"]
    g7 = of_class(f, "G7")[0]
    assert g7["identity_id"] == "datadog:DATADOG_API_KEY"
    assert g7["severity"] == "critical" and f["summary"]["exit_code"] == 1


def test_G7_new_mcp_server_non_production_warning(tmp_path):
    repo = base_repo(tmp_path)
    m = json.loads(MCP)
    m["mcpServers"]["linear"] = {"type": "http", "url": "https://mcp.linear.app/mcp"}
    write(repo, {".mcp.json": json.dumps(m, indent=2)})
    f = run_check(repo)
    assert classes(f) == ["G7"]
    assert of_class(f, "G7")[0]["identity_id"] == "linear:oauth:mcp.linear.app"
    assert f["summary"]["exit_code"] == 0


def test_G7_new_declaration(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".env.example": "GITHUB_PERSONAL_ACCESS_TOKEN=\nSTRIPE_SECRET_KEY=\n"})
    g7 = of_class(run_check(repo), "G7")
    assert [g["identity_id"] for g in g7] == ["stripe:STRIPE_SECRET_KEY"]


# ---------------------------------------------------------------- G8 -------

def test_G8_server_removed_but_still_declared(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".mcp.json": '{"mcpServers": {}}\n'})
    f = run_check(repo)
    g8 = of_class(f, "G8")
    assert [(g["identity_id"], g["component"]["name"], g["change"]) for g in g8] == [
        ("github:GITHUB_PERSONAL_ACCESS_TOKEN", "github", "removed")]
    assert g8[0]["line"] is None
    assert classes(f) == ["G8"]


def test_G8_job_removed(tmp_path):
    repo = base_repo(tmp_path)
    wf = DEPLOY.split("  deploy:\n")[0]
    write(repo, {".github/workflows/deploy.yml": wf})
    g8 = of_class(run_check(repo), "G8")
    assert sorted(g["identity_id"] for g in g8) == [
        "aws:oidc:arn:aws:iam::123456789012:role/gha-deploy",
        "github:GITHUB_TOKEN@.github/workflows/deploy.yml#deploy",
    ]


def test_G8_not_raised_while_still_used(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".env.example": None})  # declaration removed, server still uses it
    f = run_check(repo)
    assert of_class(f, "G8") == []
    assert any(d["kind"] == "binding_removed" for d in f["drift"])


# --------------------------------------------------------- severity policy ---

def test_policy_override_and_off(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/CODEOWNERS": None})
    pol = merge_policy({"schema_version": "1.0", "document": "grantlock.policy",
                        "severity": {"G4": {"production": "critical", "non_production": "off"}}})
    f = run_check(repo, pol)
    g4 = of_class(f, "G4")
    assert g4 and all(g["production"]["value"] for g in g4)
    assert all(g["severity"] == "critical" for g in g4)
    assert f["summary"]["exit_code"] == 1


def test_custom_production_patterns(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".mcp.json": MCP.replace('"repos"', '"repos,issues"')})
    pol = merge_policy({"schema_version": "1.0", "document": "grantlock.policy",
                        "production_patterns": ["github-mcp-server"]})
    g2 = of_class(run_check(repo, pol), "G2")
    assert g2[0]["severity"] == "critical"
    assert g2[0]["production"]["evidence"] == ["image 'ghcr.io/github/github-mcp-server' matches production pattern"]


def test_invalid_policy_rejected():
    with pytest.raises(PolicyError):
        merge_policy({"schema_version": "1.0", "document": "grantlock.policy", "severity": {"G1": {"production": "loud", "non_production": "warning"}}})
    with pytest.raises(PolicyError):
        merge_policy({"schema_version": "1.0", "document": "grantlock.policy", "production_patterns": ["("]})


def test_default_policy_matches_spec():
    sev = default_policy()["severity"]
    for c in ("G2", "G3", "G7"):
        assert sev[c] == {"production": "critical", "non_production": "warning"}
    for c in ("G1", "G4", "G5", "G6", "G8"):
        assert sev[c] == {"production": "warning", "non_production": "warning"}


# ------------------------------------------------------------- invariants ---

def _digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest(), os.stat(p).st_mtime_ns


def test_check_never_writes_lockfile(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace("      id-token: write\n", "      id-token: write\n      packages: write\n"),
                 ".github/CODEOWNERS": None})
    lock_path = repo / "grantlock.json"
    before = _digest(lock_path)
    listing = sorted(os.listdir(repo))
    f = check(repo)
    assert f["summary"]["total"] > 0
    assert _digest(lock_path) == before
    assert sorted(os.listdir(repo)) == listing


def test_check_requires_lockfile(tmp_path):
    repo = base_repo(tmp_path)
    (repo / "grantlock.json").unlink()
    with pytest.raises(MissingLockfile):
        check(repo)
    assert not (repo / "grantlock.json").exists()


def test_findings_deterministic_and_leak_free(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".mcp.json": MCP.replace('"${GITHUB_PERSONAL_ACCESS_TOKEN}"', '"ghp_FAKEleak000000000000000000000000000"'),
                 ".github/CODEOWNERS": None})
    a, b = run_check(repo), run_check(repo)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert_no_secret_leak(a)


def test_relock_resolves_diff_classes(tmp_path):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace(
        "      - run: ./deploy.sh", "      - run: ./deploy.sh\n        env:\n          DATADOG_API_KEY: ${{ secrets.DATADOG_API_KEY }}")})
    assert run_check(repo)["summary"]["exit_code"] == 1
    relock(repo)  # human accepts the change
    f = run_check(repo)
    assert f["findings"] == [] and f["summary"]["lock_in_sync"]
