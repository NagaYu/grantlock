from pathlib import Path

from grantlock import model
from grantlock.parsers.terraform import build, load_blocks, parse_terraform, string_value
from secret_guard import assert_no_secret_leak

FX = Path(__file__).parent / "fixtures" / "terraform"
SECRETS = [
    "AKIAFAKETFPROVIDR234",
    "FAKEtfProviderSecret0000000000000000000000",
    "sk-proj-FAKEtfVarDefault00000000000000000000000000000000000T3BlbkFJ00000000000000000000000000000000000000000000000000000",
    "FAKEtfDbPassword42",
]


def _all():
    blocks, warns = [], []
    for p in sorted(FX.rglob("*.tf")):
        b, w = load_blocks(p.relative_to(FX).as_posix(), p.read_text())
        blocks += b
        warns += w
    entries, w2 = build(blocks)
    return entries, warns + w2


def _find(entries, identity, comp):
    hits = [e for e in entries if e["identity_id"] == identity and e["component"]["name"] == comp]
    assert len(hits) == 1, (identity, comp, sorted({(e["identity_id"], e["component"]["name"]) for e in entries}))
    return hits[0]


def test_broken_file_warns_without_crashing():
    entries, warnings = _all()
    assert [w["file"] for w in warnings] == ["broken.tf"]
    assert entries


def test_unsupported_syntax_is_tolerated():
    text = '''
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}
locals {
  ids = [for s in var.subnets : s.id if s.public]
  m   = { for k, v in var.x : k => v }
  c   = var.enabled ? 1 : 0   # trailing comment
}
dynamic_thing "a" "b" "c" {
  nested { deep { x = 1 } }
}
'''
    entries, warnings = parse_terraform("main.tf", text)
    assert warnings == [] and entries == []


def test_policy_document_scopes_on_principal_with_component_where_written():
    entries, _ = _all()
    e = _find(entries, "aws:terraform:infra//aws_iam_role.deploy", "data.aws_iam_policy_document.deploy")
    assert e["component"]["kind"] == "terraform" and e["component"]["file"] == "infra/iam.tf"
    # Deny statements are not grants
    assert e["scopes"] == ["iam:action:ecs:DescribeServices", "iam:action:ecs:UpdateService",
                           "iam:resource:arn:aws:ecs:us-east-1:111122223333:service/agents/*"]
    assert model.wildcard_reasons(e["scopes"]) == []  # ARN with /* is not a wildcard grant


def test_heredoc_json_policy_and_managed_admin_policy():
    entries, _ = _all()
    inline = _find(entries, "aws:terraform:infra//aws_iam_role.agent", "aws_iam_role_policy.agent")
    assert "iam:action:s3:*" in inline["scopes"] and "iam:resource:*" in inline["scopes"]
    reasons = model.wildcard_reasons(inline["scopes"])
    assert any("s3:*" in r for r in reasons) and any("Resource '*'" in r for r in reasons)
    adm = _find(entries, "aws:terraform:infra//aws_iam_role.agent", "aws_iam_role_policy_attachment.agent_admin")
    assert adm["scopes"] == ["iam:managed:AdministratorAccess"] and model.wildcard_reasons(adm["scopes"])


def test_roles_are_federated_and_trust_recorded():
    entries, _ = _all()
    role = _find(entries, "aws:terraform:infra//aws_iam_role.deploy", "aws_iam_role.deploy")
    assert role["credential"]["storage"] == "federated" and role["lifespan"] == "ephemeral"
    assert {"kind": "cloud_resource", "value": "trust:web-identity"} in role["resources"]


def test_consumers_share_role():
    entries, _ = _all()
    users = sorted(e["component"]["name"] for e in entries
                   if e["identity_id"] == "aws:terraform:infra//aws_iam_role.agent" and e["component"]["kind"] == "terraform_workload")
    assert users == ["aws_ecs_task_definition.agent", "aws_lambda_function.agent"]  # G5 material


def test_static_keys_are_long_lived_with_federation_context():
    entries, _ = _all()
    k = _find(entries, "aws:terraform:infra//aws_iam_access_key.ci", "aws_iam_access_key.ci")
    assert k["lifespan"] == "long_lived" and k["context"]["federation_available"] is True
    assert "already defined" in k["context"]["reason"]
    g = _find(entries, "gcp:terraform:infra//google_service_account_key.agent", "google_service_account_key.agent")
    assert g["credential"]["type"] == "service_account" and g["context"]["federation_available"] is True


def test_gcp_and_azure_admin_roles():
    entries, _ = _all()
    ed = _find(entries, "gcp:terraform:infra//google_service_account.agent", "google_project_iam_member.agent_editor")
    assert ed["scopes"] == ["role:roles/editor"] and model.wildcard_reasons(ed["scopes"])
    logs = _find(entries, "gcp:terraform:infra//google_service_account.agent", "google_project_iam_member.agent_logs")
    assert model.wildcard_reasons(logs["scopes"]) == []
    az = _find(entries, "azure:terraform:infra//azurerm_user_assigned_identity.agent", "azurerm_role_assignment.agent_owner")
    assert az["scopes"] == ["role:Owner"] and model.wildcard_reasons(az["scopes"])


def test_literals_classified_and_discarded():
    entries, _ = _all()
    prov = _find(entries, "aws:terraform:infra/envs/prod//provider.aws.access_key", "provider.aws")
    assert prov["credential"]["storage"] == "inline"
    assert prov["credential"]["format"] == {"class": "aws_access_key_id", "prefix": "AKIA"}
    assert prov["context"]["federation_available"] is True  # static key where federation exists
    assert len(prov["evidence"]) == 2  # access_key + secret_key merged
    var = _find(entries, "openai:terraform:infra/envs/prod//var.openai_api_key.default", "var.openai_api_key")
    assert var["credential"]["format"]["class"] == "openai_key"
    db = _find(entries, "aws:terraform:infra/envs/prod//aws_db_instance.agent.password", "aws_db_instance.agent")
    assert db["credential"]["format"]["class"] == "generic_literal"
    assert {"kind": "environment", "value": "prod"} in db["resources"]
    # non-secret literals (region, cidr, tags, interpolations) produce nothing
    assert not any("region" in e["identity_id"] or "cidr" in e["identity_id"] for e in entries)


def test_values_never_in_output():
    entries, warnings = _all()
    assert_no_secret_leak(entries, SECRETS)
    assert_no_secret_leak(warnings, SECRETS)


def test_string_value_helper():
    assert string_value('"abc"') == "abc"
    assert string_value('"a-${var.x}"') is None
    assert string_value("<<EOT\nhello\nEOT") == "hello"
    assert string_value("var.x") is None


def test_deterministic():
    assert _all() == _all()
