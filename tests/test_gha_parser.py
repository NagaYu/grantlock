from pathlib import Path

import pytest

from grantlock.parsers.gha import normalize_permissions, parse_workflow, _MISSING
from grantlock import model
from secret_guard import assert_no_secret_leak

FX = Path(__file__).parent / "fixtures" / "gha"


def _parse(name):
    return parse_workflow(f".github/workflows/{name}", (FX / name).read_text())


def _find(entries, identity, job=None):
    hits = [e for e in entries if e["identity_id"] == identity and (job is None or e["component"]["name"].endswith("/" + job))]
    assert len(hits) == 1, (identity, [e["identity_id"] for e in entries])
    return hits[0]


# --- permissions normalization -----------------------------------------------

def test_normalize_missing_is_implicit_default():
    assert normalize_permissions(_MISSING) == ([], "implicit_default", False)


def test_normalize_read_all_write_all_expand_all_scopes():
    s, src, known = normalize_permissions("read-all")
    assert src == "read-all" and known and len(s) == 13 and all(x.endswith(":read") for x in s)
    s, src, known = normalize_permissions("write-all")
    assert src == "write-all" and len(s) == 13 and "id-token:write" in s


def test_normalize_dict_drops_none_and_sorts():
    assert normalize_permissions({"pull-requests": "write", "contents": "read", "issues": "none"}) == (
        ["contents:read", "pull-requests:write"], "explicit", True)
    assert normalize_permissions({}) == ([], "explicit", True)


def test_expand_scopes_write_implies_read():
    assert model.expand_scopes(["contents:write"]) == {"contents:read", "contents:write"}


# --- ci.yml ------------------------------------------------------------------

def test_ci_job_permissions_and_inheritance():
    entries, warnings = _parse("ci.yml")
    assert warnings == []
    test = _find(entries, "github:GITHUB_TOKEN@.github/workflows/ci.yml#test")
    assert test["scopes"] == ["contents:read"] and test["scope_source"] == "explicit"
    assert test["component"] == {"id": "gha_workflow:.github/workflows/ci.yml#test", "kind": "gha_workflow",
                                 "name": "CI/test", "file": ".github/workflows/ci.yml"}
    assert test["lifespan"] == "ephemeral"
    lint = _find(entries, "github:GITHUB_TOKEN@.github/workflows/ci.yml#lint")
    assert lint["scopes"] == [] and lint["scopes_known"] is True
    image = _find(entries, "github:GITHUB_TOKEN@.github/workflows/ci.yml#image")
    assert image["scopes"] == ["contents:read", "packages:write"]
    # secrets.GITHUB_TOKEN maps onto the job token, not a new identity
    assert len(entries) == 3
    assert {"kind": "branch", "value": "main"} in test["resources"]


# --- deploy.yml (federated) --------------------------------------------------

def test_oidc_aws_federated():
    entries, warnings = _parse("deploy.yml")
    assert warnings == []
    aws = _find(entries, "aws:oidc:arn:aws:iam::123456789012:role/gha-deploy")
    assert aws["credential"]["storage"] == "federated"
    assert aws["lifespan"] == "ephemeral"
    assert aws["scopes"] == ["role:gha-deploy"]
    assert {"kind": "environment", "value": "production"} in aws["resources"]
    assert aws["context"]["federation_available"] is False


def test_oidc_gcp_absorbs_identifier_secret():
    entries, _ = _parse("deploy.yml")
    gcp = _find(entries, "gcp:oidc:deployer@example-project.iam.gserviceaccount.com")
    assert gcp["credential"]["storage"] == "federated"
    assert {"kind": "environment", "value": "staging"} in gcp["resources"]
    # WIF_PROVIDER is an identifier of the federated principal, not a credential
    assert not any("WIF_PROVIDER" in e["identity_id"] for e in entries)


# --- legacy.yml (static keys, inline, implicit default, write-all) ------------

def test_legacy_on_true_and_implicit_default():
    entries, warnings = _parse("legacy.yml")
    rel = _find(entries, "github:GITHUB_TOKEN@.github/workflows/legacy.yml#release")
    assert rel["scope_source"] == "implicit_default" and rel["scopes_known"] is False
    assert {"kind": "trigger", "value": "push"} in rel["resources"]
    # component name falls back to the file stem when `name:` is absent
    assert rel["component"]["name"] == "legacy/release"


def test_static_aws_key_pair_is_one_identity_with_federation_context():
    entries, _ = _parse("legacy.yml")
    aws = _find(entries, "aws:AWS_ACCESS_KEY_ID", job="release")
    assert aws["credential"]["storage"] == "vault_ref"
    assert aws["lifespan"] == "long_lived"
    assert aws["context"]["federation_available"] is True
    assert "OIDC" in aws["context"]["reason"]


def test_static_inputs_of_auth_actions_get_provider():
    entries, _ = _parse("legacy.yml")
    sa = _find(entries, "gcp:DEPLOY_SA")
    assert sa["credential"]["type"] == "service_account"
    assert sa["context"]["federation_available"] is True
    pypi = _find(entries, "pypi:PYPI_API_TOKEN")
    assert pypi["context"]["federation_available"] is True


def test_if_condition_secret_reference():
    entries, _ = _parse("legacy.yml")
    hook = _find(entries, "slack:SLACK_WEBHOOK")
    assert hook["credential"]["type"] == "token"


def test_inline_literals_in_workflow_env_and_run():
    entries, _ = _parse("legacy.yml")
    inline = sorted((e["identity_id"], e["credential"]["format"]["class"]) for e in entries
                    if e["credential"]["storage"] == "inline")
    assert inline == [
        ("openai:OPENAI_API_KEY", "openai_key"),  # workflow env -> attributed to release + admin jobs
        ("openai:OPENAI_API_KEY", "openai_key"),
        ("slack:gha_workflow:.github/workflows/legacy.yml#release:jobs.release.steps[2].run", "slack_token"),
    ]


def test_write_all_marks_source():
    entries, _ = _parse("legacy.yml")
    adm = _find(entries, "github:GITHUB_TOKEN@.github/workflows/legacy.yml#admin")
    assert adm["scope_source"] == "write-all"
    assert model.wildcard_reasons(adm["scopes"], adm["scope_source"])


def test_secrets_inherit_warns():
    _, warnings = _parse("legacy.yml")
    assert any("secrets: inherit" in w["message"] for w in warnings)


def test_no_secret_values_in_gha_output():
    for name in ("ci.yml", "deploy.yml", "legacy.yml"):
        entries, warnings = _parse(name)
        assert_no_secret_leak(entries)
        assert_no_secret_leak(warnings)


def test_oidc_without_id_token_warns():
    text = """
on: push
permissions:
  contents: read
jobs:
  d:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.ROLE_ARN }}
          aws-region: us-east-1
"""
    entries, warnings = parse_workflow(".github/workflows/x.yml", text)
    assert any("id-token" in w["message"] for w in warnings)
    fed = [e for e in entries if e["credential"]["storage"] == "federated"]
    assert fed[0]["identity_id"] == "aws:oidc:secrets.ROLE_ARN"
    assert not any(e["identity_id"] == "aws:ROLE_ARN" for e in entries)


def test_invalid_yaml_warns():
    entries, warnings = parse_workflow(".github/workflows/bad.yml", "jobs: [unclosed")
    assert entries == [] and warnings


@pytest.mark.parametrize("name", ["ci.yml", "deploy.yml", "legacy.yml"])
def test_evidence_lines_point_into_file(name):
    entries, _ = _parse(name)
    n = len((FX / name).read_text().splitlines())
    for e in entries:
        for ev in e["evidence"]:
            assert 1 <= ev["line"] <= n
