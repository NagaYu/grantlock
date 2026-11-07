"""Fix round Step 4 (D-043): resources that reference credential variables are users of that identity."""

from grantlock.parsers.terraform import parse_terraform
from repo_builder import of_class, relock, run_check, write

VARS = '''variable "old_ledger_db_password" {
  type      = string
  sensitive = true
}

variable "region" {
  type    = string
  default = "us-east-1"
}
'''
MAIN = '''resource "aws_db_instance" "ledger" {
  identifier = "ledger"
  engine     = "postgres"
  username   = "ledger"
  password   = var.old_ledger_db_password
  tags       = { region = var.region }
}
'''


def _repo(tmp_path, files):
    repo = tmp_path / "r"
    repo.mkdir()
    write(repo, dict({".github/CODEOWNERS": "* @acme/infra\n"}, **files))
    relock(repo)
    return repo


def test_declaration_and_reference_entries():
    entries, _ = parse_terraform("variables.tf", VARS)
    assert [(e["identity_id"], e["component"]["name"], e["component"]["kind"]) for e in entries] == [
        ("postgres:terraform:var.old_ledger_db_password", "var.old_ledger_db_password", "terraform")]
    from grantlock.parsers.terraform import build, load_blocks
    blocks = load_blocks("variables.tf", VARS)[0] + load_blocks("main.tf", MAIN)[0]
    got = {(e["identity_id"], e["component"]["name"], e["component"]["kind"]) for e in build(blocks)[0]}
    assert ("postgres:terraform:var.old_ledger_db_password", "aws_db_instance.ledger", "terraform_workload") in got
    assert not any("region" in i for i, _, _ in got)  # non-credential variables are not identities


def test_reference_dropped_is_G8_at_the_former_user(tmp_path):
    repo = _repo(tmp_path, {"variables.tf": VARS, "main.tf": MAIN})
    write(repo, {"main.tf": MAIN.replace("  password   = var.old_ledger_db_password\n", "  manage_master_user_password = true\n")})
    f = run_check(repo)
    g8 = of_class(f, "G8")
    assert [(g["component"]["name"], g["file"]) for g in g8] == [("aws_db_instance.ledger", "main.tf")]


def test_two_resources_sharing_a_credential_variable_is_G5(tmp_path):
    repo = _repo(tmp_path, {"variables.tf": VARS, "main.tf": MAIN})
    write(repo, {"main.tf": MAIN + MAIN.replace('"ledger"', '"replica"', 1)})
    assert sorted(g["component"]["name"] for g in of_class(run_check(repo), "G5")) == ["aws_db_instance.ledger", "aws_db_instance.replica"]


def test_provider_blocks_are_not_double_counted():
    text = 'variable "aws_access_key_id" {}\nprovider "aws" {\n  access_key = var.aws_access_key_id\n}\n'
    kinds = sorted(e["component"]["kind"] for e in parse_terraform("p.tf", text)[0])
    assert kinds == ["terraform", "terraform"]  # the variable declaration + the provider static identity (D-041), no extra user
