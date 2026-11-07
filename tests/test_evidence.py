"""Step 6: evidence pack — schema, no secret values, control mapping, lock history, CLI."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

import grantlock
from grantlock import lockfile, schemas
from grantlock.check import evidence
from grantlock.cli import main
from grantlock.evidence import CONTROL_MAP, DISCLAIMER, render_markdown
from repo_builder import DEPLOY, MCP, base_repo, write
from repo_builder2 import COMPOSE, base_repo2
from secret_guard import FIXTURE_SECRETS, assert_no_secret_leak

ROOT = Path(__file__).parents[1]
LEAK = "sk-ant-api03-FAKEevid0000000000000000000000000000000000000000000000000000000000000000000000000000000000AA"


@pytest.fixture
def leaky(tmp_path):
    repo = tmp_path / "r"
    shutil.copytree(ROOT / "tests" / "fixtures" / "repo_basic", repo)
    lockfile.write(repo / "grantlock.json", grantlock.lock(grantlock.scan(repo)))
    write(repo, {".github/CODEOWNERS": None})
    return repo


def test_schema_valid_and_disclaimer(leaky):
    ev = evidence(leaky)
    schemas.validate(ev, schemas.DOC_EVIDENCE)
    assert ev["disclaimer"] == DISCLAIMER and "not" in ev["disclaimer"]
    assert ev["control_mapping"]["nature"].startswith("suggestive")
    assert ev["inventory_summary"]["unowned_bindings"] == ev["inventory_summary"]["bindings"]
    assert ev["findings_summary"]["by_class"]["G1"] >= 1


def test_control_table_covers_ia5_ac6_cc6():
    assert set(CONTROL_MAP) == {f"G{i}" for i in range(1, 9)}
    ids = {c for v in CONTROL_MAP.values() for c in v}
    assert {"IA-5", "AC-6", "CC6.1", "CC6.6"} <= ids
    assert "IA-5(7)" in CONTROL_MAP["G1"] and "AC-6" in CONTROL_MAP["G3"]


def test_every_finding_carries_controls_and_rationale(leaky):
    ev = evidence(leaky)
    for f in ev["findings"]:
        assert f["controls"] == CONTROL_MAP[f["class"]]
        assert f["rationale"]


def test_no_secret_values_in_json_or_markdown(leaky, tmp_path):
    ev = evidence(leaky)
    assert_no_secret_leak(ev)
    assert_no_secret_leak(render_markdown(ev))
    repo = base_repo2(tmp_path)
    write(repo, {"compose.yaml": COMPOSE.replace("${ANTHROPIC_API_KEY}", LEAK)})
    ev2 = evidence(repo)
    assert ev2["findings_summary"]["by_class"] == {"G1": 1}
    assert_no_secret_leak(ev2, [LEAK])
    assert_no_secret_leak(render_markdown(ev2), [LEAK])


def test_lock_history_summary(tmp_path):
    repo = base_repo(tmp_path)
    prev = tmp_path / "prev.json"
    shutil.copy(repo / "grantlock.json", prev)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace("      id-token: write\n", "      id-token: write\n      packages: write\n"),
                 ".env.example": "GITHUB_PERSONAL_ACCESS_TOKEN=\nSTRIPE_SECRET_KEY=\n"})
    lockfile.write(repo / "grantlock.json", grantlock.lock(grantlock.scan(repo)))
    ev = evidence(repo, previous_lock_path=prev)
    lh = ev["lock_history"]
    assert lh["identities_added"] == 1 and lh["bindings_added"] == 1 and lh["bindings_with_scope_changes"] == 1
    assert "1 binding(s) with scope changes" in render_markdown(ev)
    assert evidence(repo)["lock_history"] is None


def test_cli_evidence_writes_pack_and_not_lockfile(leaky, tmp_path, capsys):
    before = hashlib.sha256((leaky / "grantlock.json").read_bytes()).hexdigest()
    out = tmp_path / "pack"
    assert main(["evidence", "--repo", str(leaky), "--output-dir", str(out)]) == 0
    doc = json.loads((out / "grantlock-evidence.json").read_text())
    schemas.validate(doc, schemas.DOC_EVIDENCE)
    md = (out / "grantlock-evidence.md").read_text()
    assert "Suggestive mapping only" in md and "IA-5" in md and "CC6.1" in md
    assert hashlib.sha256((leaky / "grantlock.json").read_bytes()).hexdigest() == before
    assert_no_secret_leak((out / "grantlock-evidence.json").read_text())
    assert_no_secret_leak(md)


def test_evidence_requires_lockfile(tmp_path, capsys):
    repo = base_repo(tmp_path)
    (repo / "grantlock.json").unlink()
    assert main(["evidence", "--repo", str(repo), "--output-dir", str(tmp_path / "x")]) == 2


def test_evidence_schema_rejects_values():
    ev = {"schema_version": "1.0", "document": "grantlock.evidence"}
    assert schemas.validation_errors(ev, schemas.DOC_EVIDENCE)
