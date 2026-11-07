"""Fix round Step 2 (D-041): provider-block credentials are first-class identities."""

import grantlock
from grantlock.parsers.terraform import parse_terraform
from repo_builder import of_class, relock, run_check, write
from secret_guard import assert_no_secret_leak

FED = '''provider "aws" {
  region = "us-east-1"
  assume_role {
    role_arn = "arn:aws:iam::111122223333:role/terraform-deployer"
  }
}
'''
STATIC = '''provider "aws" {
  region     = "us-east-1"
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
}
'''
CODEOWNERS = {".github/CODEOWNERS": "* @acme/infra\n"}


def _by(entries):
    return {e["identity_id"]: e for e in entries}


def test_assume_role_is_federated_identity():
    e = _by(parse_terraform("provider.tf", FED)[0])["aws:terraform:provider.aws.assume_role"]
    assert e["component"]["name"] == "provider.aws" and e["credential"]["storage"] == "federated"
    assert e["lifespan"] == "ephemeral"
    assert {"kind": "role", "value": "arn:aws:iam::111122223333:role/terraform-deployer"} in e["resources"]


def test_var_static_keys_are_long_lived_static_identity():
    entries, _ = parse_terraform("provider.tf", STATIC)
    e = _by(entries)["aws:terraform:provider.aws.access_key"]
    assert e["credential"]["storage"] == "env" and e["credential"]["format"] is None
    assert e["lifespan"] == "long_lived" and e["context"]["federation_available"] is True
    assert len([x for x in entries if x["component"]["name"] == "provider.aws"]) == 1  # key pair = one identity


def test_switch_from_assume_role_to_static_keys(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    write(repo, dict(CODEOWNERS, **{"provider.tf": FED}))
    relock(repo)
    write(repo, {"provider.tf": STATIC})
    f = run_check(repo)
    g6 = of_class(f, "G6")
    assert [(g["component"]["name"], g["file"]) for g in g6] == [("provider.aws", "provider.tf")]
    assert [g["identity_id"] for g in of_class(f, "G7")] == ["aws:terraform:provider.aws.access_key"]
    assert [g["identity_id"] for g in of_class(f, "G8")] == ["aws:terraform:provider.aws.assume_role"]


def test_literal_keys_still_inline_and_not_duplicated():
    lit = 'provider "aws" {\n  access_key = "AKIAFAKEPROVD3RTEST2"\n  secret_key = "FAKEproviderSecretValue000000000000000000"\n}\n'
    entries, _ = parse_terraform("p.tf", lit)
    prov = [e for e in entries if e["component"]["name"] == "provider.aws"]
    assert len(prov) == 1 and prov[0]["credential"]["storage"] == "inline"
    assert_no_secret_leak(entries, ["AKIAFAKEPROVD3RTEST2", "FAKEproviderSecretValue000000000000000000"])


def test_gcp_and_azure_provider_credentials():
    text = '''provider "google" {
  project     = "acme"
  credentials = file(var.gcp_key_path)
}
provider "google" {
  alias                       = "impersonated"
  impersonate_service_account = "deployer@acme.iam.gserviceaccount.com"
}
provider "azurerm" {
  features {}
  use_oidc = true
}
'''
    b = _by(parse_terraform("p.tf", text)[0])
    assert b["gcp:terraform:provider.google.credentials"]["context"]["federation_available"] is True
    assert b["gcp:terraform:provider.google.impersonated.impersonate_service_account"]["credential"]["storage"] == "federated"
    assert b["azure:terraform:provider.azurerm.oidc"]["credential"]["storage"] == "federated"


def test_provider_without_credentials_produces_nothing():
    assert parse_terraform("p.tf", 'provider "aws" {\n  region = "us-east-1"\n}\n')[0] == []
