"""Step 8 tooling: holdout scoring on a synthetic stand-in corpus (never the sealed one)."""

import hashlib
import json
from pathlib import Path

from grantbench.ext_mutations import EXT_PLANTED
from grantbench.generator import generate_ext
from grantbench.holdout_score import gate, holdout_digest, main, score_holdout


def test_digest_matches_brief_definition(tmp_path):
    (tmp_path / "cases" / "a").mkdir(parents=True)
    (tmp_path / "cases" / "a" / "x.txt").write_bytes(b"one")
    (tmp_path / "cases" / "a-b").mkdir()
    (tmp_path / "cases" / "a-b" / "y.txt").write_bytes(b"two")
    (tmp_path / "AUTHORING.md").write_text("not hashed")
    (tmp_path / "manifest.json").write_text("{}")
    h = hashlib.sha256()
    for rel, data in sorted([("cases/a/x.txt", b"one"), ("cases/a-b/y.txt", b"two")]):  # str order: '-' < '/'
        h.update(rel.encode() + b"\0" + data + b"\0")
    assert holdout_digest(tmp_path) == h.hexdigest()


def test_gate_bar():
    def mk(r2, r3, r7, fp):
        return {"recall_by_class": {"G2": {"recall": r2}, "G3": {"recall": r3}, "G7": {"recall": r7}},
                "clean": {"fp_rate": fp}}
    assert gate(mk(1.0, 0.875, 1.0, 0.0))["criterion_4_pass"] is True        # 1 miss in 24
    assert gate(mk(0.875, 0.875, 0.875, 0.0))["criterion_4_pass"] is False   # 3 misses: avg 0.875 < 0.9
    assert gate(mk(0.75, 1.0, 1.0, 0.0))["criterion_4_pass"] is False        # a class below 80%
    assert gate(mk(1.0, 1.0, 1.0, 0.0625))["criterion_4_pass"] is False      # clean FP above 5%
    assert gate(mk(None, 1.0, 1.0, 0.0))["criterion_4_pass"] is False


def test_numbers_only_and_read_only(tmp_path):
    corpus = tmp_path / "stand-in"
    generate_ext(corpus)  # a stand-in with the same layout; the sealed holdout is never touched by tests
    m = json.loads((corpus / "manifest.json").read_text())
    m["corpus_sha256"] = holdout_digest(corpus)
    (corpus / "manifest.json").write_text(json.dumps(m))
    before = {p: p.read_bytes() for p in corpus.rglob("*") if p.is_file()}
    res = score_holdout(corpus, which=lambda n: None)
    assert {p: p.read_bytes() for p in corpus.rglob("*") if p.is_file()} == before
    assert res["hash_match"] is True
    text = json.dumps(res, default=list)
    assert "dev-ext-" not in text and "compose.yaml" not in text and "deploy/k8s" not in text
    assert res["baselines"]["gitleaks"]["status"] == "NOT RUN"
    assert set(res["gate_strict"]) == {"headline_recall", "headline_average", "clean_fp_rate", "criterion_4_pass"}


def test_cli_not_run_when_corpus_absent(tmp_path, capsys):
    assert main(["--corpus", str(tmp_path / "missing"), "--out", str(tmp_path / "o.json")]) == 3
    assert "NOT RUN" in capsys.readouterr().out
    assert not (tmp_path / "o.json").exists()
