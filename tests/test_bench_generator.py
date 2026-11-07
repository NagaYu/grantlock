import json
from pathlib import Path

import pytest

import grantlock
from grantlock import lockfile
from grantbench import generator
from grantbench.generator import (CASE_SCHEMA, HoldoutRefused, REPO_ROOT, check_holdout_allowed, generate,
                                  validate_case)
from grantbench.mutations import DIFF_PAIRS, PLANTED, Sink


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    out = tmp_path_factory.mktemp("bench") / "dev"
    sink = Sink()
    manifest = generate("dev", out, sink=sink)
    return out, manifest, sink


def _cases(out):
    return [json.loads(p.read_text()) for p in sorted((out / "cases").glob("*/case.json"))]


def test_counts(corpus):
    out, m, _ = corpus
    assert m["counts"] == {"planted": 80, "clean": 24, "diff_pair": 16, "total": 120,
                           "planted_by_class": {f"G{i}": 10 for i in range(1, 9)}}
    cases = _cases(out)
    assert len(cases) == 120
    assert {c["lang"] for c in cases} == {"en", "ja"}
    for cls in [f"G{i}" for i in range(1, 9)]:
        planted = [c for c in cases if c["kind"] == "planted" and c["case_id"].split("-")[2] == cls]
        assert len(planted) == 10
        assert all(any(p["class"] == cls for p in c["planted"]) for c in planted)


def test_every_class_has_variety():
    for cls, variants in PLANTED.items():
        assert len(variants) >= 6, cls
    assert len(DIFF_PAIRS) == 16


def test_deterministic(corpus, tmp_path):
    out, m, _ = corpus
    m2 = generate("dev", tmp_path / "again")
    assert m2["corpus_sha256"] == m["corpus_sha256"]
    files1 = sorted(p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file())
    files2 = sorted(p.relative_to(tmp_path / "again").as_posix() for p in (tmp_path / "again").rglob("*") if p.is_file())
    assert files1 == files2


def test_case_files_schema_valid(corpus):
    out, _, _ = corpus
    for c in _cases(out):
        assert validate_case(c) == [], c["case_id"]
        root = out / "cases" / c["case_id"]
        if c["kind"] == "diff_pair":
            assert (root / "before" / "grantlock.json").is_file() and (root / "after" / "grantlock.json").is_file()
            assert (root / "before" / "grantlock.json").read_text() == (root / "after" / "grantlock.json").read_text()
            assert c["expected_labels"] == sorted(c["expected_labels"])
        else:
            assert (root / "repo" / "grantlock.json").is_file()
            lockfile.loads((root / "repo" / "grantlock.json").read_text())


def test_case_schema_rejects_bad_docs():
    good = {"schema_version": "1.0", "document": "grantbench.case", "case_id": "dev-clean-01", "split": "dev",
            "kind": "clean", "lang": "en", "planted": [], "expected_labels": [], "description": "x"}
    assert validate_case(good) == []
    assert validate_case(dict(good, kind="planted"))  # planted needs >= 1 planted item
    assert validate_case(dict(good, lang="fr"))
    assert validate_case(dict(good, secret="x"))
    bad = dict(good, kind="clean", planted=[{"class": "G1", "file": "a", "component": "b", "note": "c"}])
    assert validate_case(bad)


def test_planted_mutations_take_effect(corpus):
    """Every planted/diff mutation changes the identity inventory relative to the committed lock
    (except the benign diff pairs whose label set is empty, which may only touch text)."""
    out, _, _ = corpus
    for c in _cases(out):
        if c["kind"] == "clean":
            continue
        repo = out / "cases" / c["case_id"] / ("after" if c["kind"] == "diff_pair" else "repo")
        committed = lockfile.read(repo / "grantlock.json")
        current = grantlock.lock(grantlock.scan(repo))
        if c["kind"] == "planted" or c["expected_labels"]:
            assert current["entries"] != committed["entries"], c["case_id"]


def test_planted_files_exist(corpus):
    out, _, _ = corpus
    for c in _cases(out):
        if c["kind"] != "planted":
            continue
        for p in c["planted"]:
            if p["class"] != "G8":
                assert (out / "cases" / c["case_id"] / "repo" / p["file"]).is_file(), (c["case_id"], p)


def test_clean_cases_lock_in_sync(corpus):
    out, _, _ = corpus
    for c in _cases(out):
        if c["kind"] == "clean":
            repo = out / "cases" / c["case_id"] / "repo"
            assert lockfile.dumps(grantlock.lock(grantlock.scan(repo))) == (repo / "grantlock.json").read_text()


def test_fixture_secrets_are_fake_and_never_in_expectations(corpus):
    out, _, sink = corpus
    assert sink.values, "G1 variants must plant dummy secrets"
    corpus_text = {p: p.read_text(encoding="utf-8") for p in out.rglob("*") if p.is_file()}
    expectation_files = [p for p in corpus_text if p.name in ("case.json", "manifest.json", "grantlock.json")]
    snapshot_text = "\n".join(t for p, t in corpus_text.items() if p not in expectation_files)
    for v in sink.values:
        assert "FAKE" in v
        assert v in snapshot_text  # planted in the snapshot...
        for p in expectation_files:  # ...but never in expectations or lockfiles
            assert v not in corpus_text[p]


# ------------------------------------------------------------------ holdout ---

def test_holdout_refused_without_env(tmp_path):
    with pytest.raises(HoldoutRefused, match="GRANTLOCK_ALLOW_HOLDOUT"):
        check_holdout_allowed(tmp_path / "h", env={})
    assert not (tmp_path / "h").exists()


def test_holdout_refused_inside_repo_even_with_env():
    with pytest.raises(HoldoutRefused, match="outside the repository"):
        check_holdout_allowed(REPO_ROOT / "bench" / "holdout", env={"GRANTLOCK_ALLOW_HOLDOUT": "1"})
    with pytest.raises(HoldoutRefused):
        check_holdout_allowed(REPO_ROOT, env={"GRANTLOCK_ALLOW_HOLDOUT": "1"})


def test_holdout_refused_with_wrong_env_value(tmp_path):
    with pytest.raises(HoldoutRefused):
        check_holdout_allowed(tmp_path / "h", env={"GRANTLOCK_ALLOW_HOLDOUT": "true"})


def test_holdout_guard_allows_only_outside_plus_env(tmp_path):
    # guard only; Phase 1 never actually generates holdout
    check_holdout_allowed(tmp_path / "h", env={"GRANTLOCK_ALLOW_HOLDOUT": "1"})


def test_generate_holdout_refused_and_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("GRANTLOCK_ALLOW_HOLDOUT", raising=False)
    with pytest.raises(HoldoutRefused):
        generate("holdout", tmp_path / "h")
    assert not (tmp_path / "h").exists()
    target = REPO_ROOT / "bench" / "holdout-should-not-exist"
    monkeypatch.setenv("GRANTLOCK_ALLOW_HOLDOUT", "1")
    with pytest.raises(HoldoutRefused):
        generate("holdout", target)
    assert not target.exists()


def test_cli_holdout_exit_code(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("GRANTLOCK_ALLOW_HOLDOUT", raising=False)
    assert generator.main(["--split", "holdout", "--out", str(tmp_path / "h")]) == 2
    assert "refused" in capsys.readouterr().err


def test_refuses_to_clobber_foreign_dir(tmp_path):
    d = tmp_path / "x"
    d.mkdir()
    (d / "keep.txt").write_text("mine")
    with pytest.raises(FileExistsError):
        generate("dev", d, force=True)
    assert (d / "keep.txt").read_text() == "mine"
