"""D-047: a detector crash during scoring counts as a failure of that case (never skipped)."""

import json

from grantbench.lockless import score_lockless


def _case(root, cid, kind, planted=()):
    d = root / "cases" / cid
    for sub in {"planted": ("base", "repo"), "clean": ("repo",), "diff_pair": ("before", "after")}[kind]:
        (d / sub).mkdir(parents=True)
    (d / "case.json").write_text(json.dumps({"case_id": cid, "kind": kind, "planted": list(planted), "expected_labels": []}))


def test_crash_is_counted_as_failure(tmp_path):
    _case(tmp_path, "holdout-planted-G2-01", "planted", [{"class": "G2", "file": "a.tf", "component": "x", "note": ""}])
    _case(tmp_path, "holdout-clean-01", "clean")
    _case(tmp_path, "holdout-diff-01", "diff_pair")

    def boom(a, b):
        raise ValueError("schema violation")

    r = score_lockless(tmp_path, checker=boom)
    assert r["recall_by_class"]["G2"] == {"detected": 0, "total": 1, "recall": 0.0}
    assert r["clean"]["fp_cases"] == 1 and r["clean"]["fp_details"][0]["classes"] == ["ERROR"]
    assert r["diff_pair"]["correct"] == 0 and r["diff_pair"]["details"][0]["predicted"] == ["ERROR"]
    assert sorted(e["kind"] for e in r["errors"]) == ["clean", "diff_pair", "planted"]
    assert {e["error"] for e in r["errors"]} == {"ValueError"}
