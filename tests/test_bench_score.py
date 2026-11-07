import json
import os
import stat
from pathlib import Path

import pytest

from grantbench import score
from grantbench.generator import generate
from repo_builder import BASE, MCP, write, relock
from secret_guard import assert_no_secret_leak


def _case(root: Path, case_id, kind, planted=(), labels=()):
    d = root / "cases" / case_id
    d.mkdir(parents=True)
    (d / "case.json").write_text(json.dumps({"case_id": case_id, "kind": kind, "planted": list(planted),
                                             "expected_labels": list(labels), "lang": "en"}))
    return d


def _repo(d: Path, sub: str, files=None, mutate=None):
    r = d / sub
    r.mkdir()
    write(r, dict(BASE, **(files or {})))
    relock(r)
    if mutate:
        write(r, mutate)
    return r


@pytest.fixture
def mini(tmp_path):
    c = tmp_path / "corpus"
    leak = MCP.replace('"${GITHUB_PERSONAL_ACCESS_TOKEN}"', '"ghp_FAKEleak000000000000000000000000000"')
    # planted G1 detected (right file + component)
    d = _case(c, "dev-planted-G1-01", "planted", [{"class": "G1", "file": ".mcp.json", "component": "github", "note": ""}])
    _repo(d, "repo", mutate={".mcp.json": leak})
    # planted G1 with a wrong component in the expectation -> miss
    d = _case(c, "dev-planted-G1-02", "planted", [{"class": "G1", "file": ".mcp.json", "component": "other", "note": ""}])
    _repo(d, "repo", mutate={".mcp.json": leak})
    # planted G4 (CODEOWNERS removed)
    d = _case(c, "dev-planted-G4-01", "planted", [{"class": "G4", "file": ".mcp.json", "component": "github", "note": ""}])
    _repo(d, "repo", mutate={".github/CODEOWNERS": None})
    # clean and a clean with a finding (FP)
    _repo(_case(c, "dev-clean-01", "clean"), "repo")
    _repo(_case(c, "dev-clean-02", "clean"), "repo", mutate={".github/CODEOWNERS": None})
    # diff pairs: one right, one wrong
    d = _case(c, "dev-diff-01", "diff_pair", labels=["G1"])
    _repo(d, "after", mutate={".mcp.json": leak})
    d = _case(c, "dev-diff-02", "diff_pair", labels=["G2"])
    _repo(d, "after", mutate={".mcp.json": leak})
    (c / "manifest.json").write_text(json.dumps({"split": "dev", "corpus_sha256": "x"}))
    return c


def test_grantlock_scoring_math(mini):
    s = score.score_grantlock(mini)
    assert s["recall_by_class"]["G1"] == {"detected": 1, "total": 2, "recall": 0.5}
    assert s["recall_by_class"]["G4"] == {"detected": 1, "total": 1, "recall": 1.0}
    assert s["recall_by_class"]["G2"] == {"detected": 0, "total": 0, "recall": None}
    assert [m["case_id"] for m in s["planted_misses"]] == ["dev-planted-G1-02"]
    assert s["clean"] == {"cases": 2, "fp_cases": 1, "fp_rate": 0.5,
                          "fp_details": s["clean"]["fp_details"]}
    assert s["clean"]["fp_details"][0]["case_id"] == "dev-clean-02"
    assert s["diff_pair"]["cases"] == 2 and s["diff_pair"]["correct"] == 1 and s["diff_pair"]["accuracy"] == 0.5
    assert_no_secret_leak(s)


def test_strict_case_level_requires_all_items(mini, tmp_path):
    d = mini / "cases" / "dev-planted-G1-01"
    doc = json.loads((d / "case.json").read_text())
    doc["planted"].append({"class": "G1", "file": ".mcp.json", "component": "missing", "note": ""})
    (d / "case.json").write_text(json.dumps(doc))
    s = score.score_grantlock(mini)
    assert s["recall_by_class"]["G1"]["detected"] == 0
    assert s["item_recall_by_class"]["G1"] == {"detected": 1, "total": 3, "recall": 0.3333}


def test_baseline_not_run_path(mini):
    res = score.score_baseline("gitleaks", mini, which=lambda name: None)
    assert res["status"] == "NOT RUN"
    assert "not found on PATH" in res["reason"]
    assert set(res["recall_by_class"].values()) == {"NOT RUN"}
    assert res["clean"] == "NOT RUN"


def test_score_all_records_not_run_honestly(mini):
    res = score.score_all(mini, which=lambda name: None)
    for name in ("gitleaks", "trufflehog"):
        assert res["baselines"][name]["status"] == "NOT RUN"
    assert res["headline"]["value_free_recall"]["G2"] is None or isinstance(res["headline"]["value_free_recall"]["G2"], float)


def test_baseline_matching_with_stub_runner(mini):
    def runner(exe, repo):
        return [{"file": ".mcp.json", "rule": "github-pat"}] if "planted-G1" in str(repo) else []
    res = score.score_baseline("gitleaks", mini, which=lambda n: "/fake/gitleaks", runner=runner)
    assert res["status"] == "ok"
    assert res["recall_by_class"]["G1"]["detected"] == 2  # file-level: the scanner sees the value
    assert res["recall_by_class"]["G4"]["detected"] == 0  # structurally invisible
    assert res["clean"]["fp_cases"] == 0


def test_baseline_failure_is_not_run(mini):
    def runner(exe, repo):
        raise OSError("boom")
    res = score.score_baseline("trufflehog", mini, which=lambda n: "/x", runner=runner)
    assert res["status"] == "NOT RUN" and "failed" in res["reason"]


def test_parse_gitleaks_drops_secret_fields(tmp_path):
    report = [{"Description": "GitHub PAT", "File": str(tmp_path / ".mcp.json"), "RuleID": "github-pat",
               "StartLine": 7, "Secret": "ghp_FAKEleak000000000000000000000000000",
               "Match": "\"ghp_FAKEleak000000000000000000000000000\"", "Fingerprint": "x"}]
    out = score.parse_gitleaks_report(report, tmp_path)
    assert out == [{"file": ".mcp.json", "rule": "github-pat"}]
    assert_no_secret_leak(out)


def test_parse_trufflehog_drops_raw(tmp_path):
    line = json.dumps({"SourceMetadata": {"Data": {"Filesystem": {"file": str(tmp_path / "a/.env")}}},
                       "DetectorName": "OpenAI", "Raw": "sk-FAKEleak0000000000000000000000",
                       "Redacted": "sk-FAKE..."})
    out = score.parse_trufflehog_lines("noise\n" + line + "\n{bad json\n", tmp_path)
    assert out == [{"file": "a/.env", "rule": "OpenAI"}]
    assert_no_secret_leak(out)


def test_run_gitleaks_with_stub_executable(tmp_path):
    """Exercise the real subprocess path against a stub binary (no real tool needed)."""
    stub = tmp_path / "gitleaks"
    stub.write_text("#!/bin/sh\n"
                    "while [ $# -gt 0 ]; do case $1 in --report-path) shift; R=$1;; --source) shift; S=$1;; esac; shift; done\n"
                    "printf '[{\"File\":\"%s/.mcp.json\",\"RuleID\":\"generic-api-key\",\"Secret\":\"REDACTED\"}]' \"$S\" > \"$R\"\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    target = tmp_path / "repo"
    target.mkdir()
    assert score.run_gitleaks(str(stub), target) == [{"file": ".mcp.json", "rule": "generic-api-key"}]


def test_score_dev_corpus_structure(tmp_path):
    """Structure only (no thresholds): the harness runs end-to-end on the generated dev corpus."""
    out = tmp_path / "dev"
    generate("dev", out)
    res = score.score_all(out, which=lambda name: None)
    gl = res["grantlock"]
    assert all(gl["recall_by_class"][c]["total"] == 10 for c in score.CLASSES)
    assert gl["clean"]["cases"] == 24 and gl["diff_pair"]["cases"] == 16
    assert set(res["headline"]) == {"value_free_recall", "value_free_recall_min", "clean_fp_rate", "criterion_5_pass"}
    assert_no_secret_leak(res)


def test_harness_controls(mini):
    """Sanity of the harness itself: a silent checker scores 0 recall, an 'everything' checker
    gets caught by the clean set."""
    empty = {"findings": []}
    s = score.score_grantlock(mini, checker=lambda repo: empty)
    assert s["recall_by_class"]["G1"]["detected"] == 0 and s["clean"]["fp_cases"] == 0

    def everything(repo):
        return {"findings": [{"class": c, "file": ".mcp.json", "component": {"name": "github"}, "finding_id": c}
                             for c in score.CLASSES]}
    s = score.score_grantlock(mini, checker=everything)
    assert s["clean"]["fp_rate"] == 1.0
    assert s["diff_pair"]["correct"] == 0
