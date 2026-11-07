"""Scoring for lockfile-less corpora (dev-ext and the sealed holdout).

Case layout: planted = base/ + repo/, clean = repo/, diff_pair = before/ + after/;
no grantlock.json anywhere. The lock is generated *in memory* from base/ (before/,
or repo/ itself for clean) and repo/ (after/) is checked against it. Nothing is
ever written into the corpus.
"""

from __future__ import annotations

import json
import os
import posixpath
from pathlib import Path
from typing import Any, Callable

import grantlock
from grantlock import policy as policy_mod

from .score import CLASSES, _ratio, target_class

# Pre-registered applicability matrix (DECISIONS D-023; .env rule from the holdout brief).
APPLICABLE: dict[str, set[str]] = {
    "mcp": set(CLASSES), "gha": set(CLASSES), "env": {"G4", "G7", "G8"},
    "compose": {"G1", "G4", "G5", "G6", "G7", "G8"}, "k8s": set(CLASSES), "terraform": set(CLASSES),
}
NEW_SURFACES = {"compose", "k8s", "terraform"}


def surface_of(path: str) -> str:
    base = posixpath.basename(path)
    if path.startswith(".github/workflows/"):
        return "gha"
    if base == ".env" or base.startswith(".env."):
        return "env"
    if base.endswith(".tf"):
        return "terraform"
    from grantlock.parsers.compose import is_compose_file
    if is_compose_file(path):
        return "compose"
    if base.endswith(".json"):
        return "mcp"
    if base.endswith((".yaml", ".yml")):
        return "k8s"
    return "other"


def check_against(lock_source: Path, target: Path) -> dict[str, Any]:
    lock = grantlock.lock(grantlock.scan(lock_source))
    pol = policy_mod.load_policy(os.path.join(target, policy_mod.POLICY_FILENAME))
    return grantlock.diff(grantlock.scan(target), lock, pol)


def _load(corpus: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((corpus / "cases").glob("*/case.json"))]


def score_lockless(corpus: str | os.PathLike[str], *, fallback_new_surfaces: bool = False,
                   checker: Callable[[Path, Path], dict[str, Any]] = check_against) -> dict[str, Any]:
    corpus = Path(corpus)
    hits = {c: [0, 0] for c in CLASSES}
    by_surface: dict[str, dict[str, list[int]]] = {}
    excluded: list[dict[str, str]] = []
    fallback_hits: list[dict[str, str]] = []
    misses: list[dict[str, Any]] = []
    clean_total = clean_fp = 0
    fp_details: list[dict[str, Any]] = []
    diff_total = diff_ok = 0
    diff_details: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []

    def run(case_id: str, kind: str, a: Path, b: Path) -> dict[str, Any] | None:
        """A crash of the detector is a failure of that case, never skipped (D-047)."""
        try:
            return checker(a, b)
        except Exception as exc:  # noqa: BLE001 - recorded, then counted as a failure
            errors.append({"case_id": case_id, "kind": kind, "error": type(exc).__name__})
            return None

    for case in _load(corpus):
        cid, kind = case["case_id"], case["kind"]
        root = corpus / "cases" / cid
        if kind == "planted":
            target = target_class(cid)
            items = [p for p in case["planted"] if p["class"] == target]
            scored = [p for p in items if target in APPLICABLE.get(surface_of(p["file"]), set(CLASSES))]
            for p in items:
                if p not in scored:
                    excluded.append({"case_id": cid, "class": target, "surface": surface_of(p["file"])})
            if not scored:
                continue
            res = run(cid, kind, root / "base", root / "repo")
            findings = res["findings"] if res is not None else []
            ok_all = True
            for it in scored:
                strict = any(f["class"] == it["class"] and f["file"] == it["file"] and f["component"]["name"] == it["component"]
                             for f in findings)
                fb = False
                if not strict and fallback_new_surfaces and surface_of(it["file"]) in NEW_SURFACES:
                    fb = any(f["class"] == it["class"] and f["file"] == it["file"] for f in findings)
                    if fb:
                        fallback_hits.append({"case_id": cid, "class": it["class"], "surface": surface_of(it["file"])})
                if not (strict or fb):
                    ok_all = False
                    misses.append({"case_id": cid, "class": target, "surface": surface_of(it["file"]),
                                   "classes_reported_for_file": sorted({f["class"] for f in findings if f["file"] == it["file"]})})
            surf = surface_of(scored[0]["file"])
            hits[target][1] += 1
            hits[target][0] += int(ok_all)
            s = by_surface.setdefault(surf, {c: [0, 0] for c in CLASSES})
            s[target][1] += 1
            s[target][0] += int(ok_all)
        elif kind == "clean":
            res = run(cid, kind, root / "repo", root / "repo")
            clean_total += 1
            if res is None or res["findings"]:
                clean_fp += 1
                fp_details.append({"case_id": cid, "classes": ["ERROR"] if res is None else sorted({f["class"] for f in res["findings"]})})
        elif kind == "diff_pair":
            res = run(cid, kind, root / "before", root / "after")
            pred = ["ERROR"] if res is None else sorted({f["class"] for f in res["findings"]})
            ok = pred == sorted(case["expected_labels"])
            diff_total += 1
            diff_ok += int(ok)
            diff_details.append({"case_id": cid, "expected": sorted(case["expected_labels"]), "predicted": pred, "correct": ok})
    return {
        "recall_by_class": {c: {"detected": hits[c][0], "total": hits[c][1], "recall": _ratio(*hits[c])} for c in CLASSES},
        "recall_by_surface": {s: {c: {"detected": v[c][0], "total": v[c][1]} for c in CLASSES if v[c][1]} for s, v in sorted(by_surface.items())},
        "excluded_out_of_scope": excluded,
        "errors": errors,
        "fallback_matches": fallback_hits,
        "planted_misses": misses,
        "clean": {"cases": clean_total, "fp_cases": clean_fp, "fp_rate": _ratio(clean_fp, clean_total), "fp_details": fp_details},
        "diff_pair": {"cases": diff_total, "correct": diff_ok, "accuracy": _ratio(diff_ok, diff_total), "details": diff_details},
    }


def score_all_lockless(corpus: str | os.PathLike[str], *, fallback_new_surfaces: bool = False,
                       which=None) -> dict[str, Any]:
    """GrantLock (lockless adapter) + baselines on the same snapshots (repo/ of planted and clean cases)."""
    import shutil

    from .score import BASELINES, score_baseline

    corpus = Path(corpus)
    manifest = json.loads((corpus / "manifest.json").read_text())
    gl = score_lockless(corpus, fallback_new_surfaces=fallback_new_surfaces)
    which = which or shutil.which
    return {
        "schema_version": "1.0",
        "document": "grantbench.scores",
        "split": manifest.get("split"),
        "corpus_sha256": manifest.get("corpus_sha256"),
        "grantlock": gl,
        "baselines": {name: score_baseline(name, corpus, which=which) for name in sorted(BASELINES)},
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="grantbench.lockless")
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out")
    ap.add_argument("--fallback-new-surfaces", action="store_true")
    args = ap.parse_args(argv)
    res = score_all_lockless(args.corpus, fallback_new_surfaces=args.fallback_new_surfaces)
    text = json.dumps(res, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    gl = res["grantlock"]
    print(json.dumps({"recall": {c: v["recall"] for c, v in gl["recall_by_class"].items()},
                      "clean_fp_rate": gl["clean"]["fp_rate"], "diff_accuracy": gl["diff_pair"]["accuracy"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
