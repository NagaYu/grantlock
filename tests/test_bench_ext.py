"""Step 5: dev-ext generator (determinism, layout, realistic dummies) and lockless scoring."""

import json
import re
from pathlib import Path

import pytest

from grantbench.ext_mutations import EXT_DIFF_PAIRS, EXT_PLANTED
from grantbench.ext_templates import real_fake
from grantbench.generator import generate_ext, validate_case
from grantbench.lockless import APPLICABLE, score_lockless, surface_of


@pytest.fixture(scope="module")
def ext(tmp_path_factory):
    out = tmp_path_factory.mktemp("ext") / "dev-ext"
    values: list[str] = []
    m = generate_ext(out, record=values)
    return out, m, values


def test_counts_and_matrix(ext):
    out, m, _ = ext
    assert m["counts"]["planted"] >= 48 and m["counts"]["clean"] == 12 and m["counts"]["diff_pair"] == 8
    assert all(v >= 6 for v in m["counts"]["planted_by_class"].values())
    for surface, per in m["planted_by_surface"].items():
        assert surface in ("compose", "k8s", "terraform")
        for cls in per:
            assert cls in APPLICABLE[surface], (surface, cls)
    assert set(m["planted_by_surface"]["compose"]) == {"G1", "G4", "G5", "G6", "G7", "G8"}


def test_deterministic(ext, tmp_path):
    _, m, _ = ext
    assert generate_ext(tmp_path / "again")["corpus_sha256"] == m["corpus_sha256"]


def test_layout_and_no_lockfiles(ext):
    out, _, _ = ext
    assert not list(out.rglob("grantlock.json"))
    for cj in sorted((out / "cases").glob("*/case.json")):
        c = json.loads(cj.read_text())
        assert validate_case(c) == [], c["case_id"]
        assert c["split"] == "dev-ext"
        subs = sorted(p.name for p in cj.parent.iterdir() if p.is_dir())
        assert subs == {"planted": ["base", "repo"], "clean": ["repo"], "diff_pair": ["after", "before"]}[c["kind"]]
        for p in c["planted"]:
            side = "base" if p["class"] == "G8" else "repo"
            if c["kind"] == "planted":
                assert (cj.parent / side / p["file"]).is_file(), (c["case_id"], p)


def test_dummies_are_format_faithful_and_marked(ext):
    out, _, values = ext
    assert values
    shapes = [r"^sk-ant-api03-[A-Za-z0-9_-]{93}AA$", r"^sk-proj-[A-Za-z0-9_-]{74}T3BlbkFJ[A-Za-z0-9_-]{74}$",
              r"^ghp_[A-Za-z0-9]{36}$", r"^AKIA[A-Z2-7]{16}$", r"^[A-Za-z0-9/+]{40}$",
              r"^xoxb-\d{11}-\d{13}-[A-Za-z0-9]{24}$", r"^FAKE[A-Za-z0-9]{20}$"]
    for v in values:
        assert "FAKE" in v
        assert any(re.match(s, v) for s in shapes), "dummy does not follow a real format"
    expectations = "\n".join(p.read_text() for p in out.rglob("*.json"))
    for v in values:
        assert v not in expectations


def test_real_fake_shapes():
    import random
    rng = random.Random(1)
    assert len(real_fake(rng, "anthropic")) == 108
    assert re.match(r"^AKIAFAKE[A-Z2-7]{12}$", real_fake(rng, "aws_id"))
    assert len(real_fake(rng, "github")) == 40


def test_surface_of():
    assert surface_of("compose.yaml") == "compose" and surface_of("deploy/k8s/rbac.yaml") == "k8s"
    assert surface_of("infra/main.tf") == "terraform" and surface_of(".github/workflows/ci.yml") == "gha"
    assert surface_of(".env.example") == "env" and surface_of(".mcp.json") == "mcp"


def test_lockless_scoring_never_writes(ext):
    out, _, _ = ext
    before = {p: p.stat().st_mtime_ns for p in out.rglob("*") if p.is_file()}
    res = score_lockless(out)
    after = {p: p.stat().st_mtime_ns for p in out.rglob("*") if p.is_file()}
    assert before == after
    assert res["clean"]["cases"] == 12 and res["diff_pair"]["cases"] == 8
    assert sum(v["total"] for v in res["recall_by_class"].values()) == 48


def test_exclusion_and_fallback_rules(tmp_path):
    """Out-of-scope surface x class items are excluded; fallback only for new surfaces."""
    root = tmp_path / "c"
    for cid, planted in (("holdout-planted-G2-01", [{"class": "G2", "file": ".env.example", "component": ".env.example", "note": ""}]),
                         ("holdout-planted-G3-01", [{"class": "G3", "file": "compose.yaml", "component": "x", "note": ""}]),
                         ("holdout-planted-G7-01", [{"class": "G7", "file": "deploy/a.yaml", "component": "wrong-name", "note": ""}])):
        d = root / "cases" / cid
        (d / "base").mkdir(parents=True)
        (d / "repo").mkdir()
        (d / "case.json").write_text(json.dumps({"case_id": cid, "kind": "planted", "planted": planted, "expected_labels": []}))

    def fake_checker(base, repo):
        return {"findings": [{"class": "G7", "file": "deploy/a.yaml", "component": {"name": "real-name"}}]}

    strict = score_lockless(root, checker=fake_checker)
    assert len(strict["excluded_out_of_scope"]) == 2
    assert strict["recall_by_class"]["G7"] == {"detected": 0, "total": 1, "recall": 0.0}
    assert strict["recall_by_class"]["G2"]["total"] == 0 and strict["recall_by_class"]["G3"]["total"] == 0
    fb = score_lockless(root, fallback_new_surfaces=True, checker=fake_checker)
    assert fb["recall_by_class"]["G7"]["detected"] == 1 and len(fb["fallback_matches"]) == 1


def test_variant_inventory():
    assert all(len(v) >= 6 for v in EXT_PLANTED.values())
    assert sum(1 for _, labels in EXT_DIFF_PAIRS if not labels) == 3
