import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from grantlock import schemas
from grantlock.cli import main
from repo_builder import DEPLOY, MCP, base_repo, write
from secret_guard import assert_no_secret_leak

ROOT = Path(__file__).parents[1]


def _sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def test_lock_then_check_in_sync(tmp_path, capsys):
    repo = base_repo(tmp_path)
    (repo / "grantlock.json").unlink()
    assert main(["lock", "--repo", str(repo)]) == 0
    assert "wrote grantlock.json" in capsys.readouterr().out
    assert main(["lock", "--repo", str(repo)]) == 0
    assert "up to date" in capsys.readouterr().out
    assert main(["check", "--repo", str(repo)]) == 0
    assert "0 critical, 0 warning" in capsys.readouterr().out


def test_check_exit_1_on_critical_and_never_writes(tmp_path, capsys):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace(
        "      - run: ./deploy.sh", "      - run: ./deploy.sh\n        env:\n          DATADOG_API_KEY: ${{ secrets.DATADOG_API_KEY }}")})
    before = _sha(repo / "grantlock.json")
    mtime = os.stat(repo / "grantlock.json").st_mtime_ns
    assert main(["check", "--repo", str(repo)]) == 1
    out = capsys.readouterr().out
    assert "CRITICAL G7" in out and "production: environment 'production'" in out
    assert _sha(repo / "grantlock.json") == before and os.stat(repo / "grantlock.json").st_mtime_ns == mtime


def test_check_json_format_is_schema_valid(tmp_path, capsys):
    repo = base_repo(tmp_path)
    write(repo, {".github/CODEOWNERS": None})
    assert main(["check", "--repo", str(repo), "--format", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    schemas.validate(doc, schemas.DOC_FINDINGS)
    assert doc["summary"]["by_class"]["G4"] > 0


def test_check_sarif_output(tmp_path, capsys):
    repo = base_repo(tmp_path)
    leak = MCP.replace('"${GITHUB_PERSONAL_ACCESS_TOKEN}"', '"ghp_FAKEleak000000000000000000000000000"')
    write(repo, {".mcp.json": leak,
                 ".github/workflows/deploy.yml": DEPLOY.replace("role/gha-deploy", "role/AdministratorAccess")})
    out_file = tmp_path / "grantlock.sarif"
    rc = main(["check", "--repo", str(repo), "--format", "sarif", "--output", str(out_file)])
    assert rc == 1
    capsys.readouterr()
    sarif = json.loads(out_file.read_text())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [f"G{i}" for i in range(1, 9)]
    rule_ids = {r["ruleId"] for r in run["results"]}
    assert {"G1", "G3", "G7", "G8"} <= rule_ids
    g1 = next(r for r in run["results"] if r["ruleId"] == "G1")
    assert g1["level"] == "warning"
    assert g1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == ".mcp.json"
    assert g1["locations"][0]["physicalLocation"]["region"]["startLine"] == 7
    assert any(r["level"] == "error" for r in run["results"])
    for r in run["results"]:
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]
    assert_no_secret_leak(out_file.read_text())


def test_missing_lockfile_exit_2(tmp_path, capsys):
    repo = base_repo(tmp_path)
    (repo / "grantlock.json").unlink()
    assert main(["check", "--repo", str(repo)]) == 2
    assert "grantlock lock" in capsys.readouterr().err
    assert not (repo / "grantlock.json").exists()


def test_invalid_lockfile_and_policy_exit_2(tmp_path, capsys):
    repo = base_repo(tmp_path)
    (repo / "grantlock.policy.json").write_text('{"schema_version": "1.0", "document": "grantlock.policy", "severity": {"G9": {}}}')
    assert main(["check", "--repo", str(repo)]) == 2
    (repo / "grantlock.policy.json").unlink()
    (repo / "grantlock.json").write_text("{broken")
    assert main(["check", "--repo", str(repo)]) == 2


def test_policy_file_in_repo_is_used(tmp_path, capsys):
    repo = base_repo(tmp_path)
    write(repo, {".github/CODEOWNERS": None})
    (repo / "grantlock.policy.json").write_text(json.dumps({
        "schema_version": "1.0", "document": "grantlock.policy",
        "severity": {"G4": {"production": "critical", "non_production": "critical"}}}))
    assert main(["check", "--repo", str(repo)]) == 1


def test_scan_command_and_no_leak(tmp_path, capsys):
    repo = tmp_path / "r"
    shutil.copytree(ROOT / "tests" / "fixtures" / "repo_basic", repo)
    assert main(["scan", "--repo", str(repo)]) == 0
    out = capsys.readouterr().out
    schemas.validate(json.loads(out), schemas.DOC_INVENTORY)
    assert_no_secret_leak(out)
    assert main(["lock", "--repo", str(repo)]) == 0
    capsys.readouterr()
    main(["check", "--repo", str(repo), "--format", "text"])
    text = capsys.readouterr().out
    assert "WARNING  G1" in text
    assert_no_secret_leak(text)
    assert_no_secret_leak((repo / "grantlock.json").read_text())


def test_python_dash_m_entrypoint(tmp_path):
    repo = base_repo(tmp_path)
    proc = subprocess.run([sys.executable, "-m", "grantlock", "check", "--repo", str(repo)],
                          capture_output=True, text=True, cwd=ROOT)
    assert proc.returncode == 0, proc.stderr
    assert "grantlock check:" in proc.stdout
