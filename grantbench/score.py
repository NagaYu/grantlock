"""Deterministic scoring harness for GrantBench (no LLM judge).

    python -m grantbench.score --corpus bench/dev --out reports/phase1_scores.json

GrantLock: per-class recall on planted cases, clean false-positive rate,
diff_pair classification accuracy.
Baselines (gitleaks / trufflehog): run only if present on PATH; otherwise
recorded as NOT RUN with the reason. Only file + rule id are kept from their
output; secret fields are discarded on parse.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

from grantlock.check import check

CLASSES = ["G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8"]
VALUE_FREE_HEADLINE = ["G2", "G3", "G7"]
NOT_RUN = "NOT RUN"


def _load_cases(corpus: Path) -> list[dict[str, Any]]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((corpus / "cases").glob("*/case.json"))]


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def target_class(case_id: str) -> str:
    """'dev-planted-G3-01' / 'dev-ext-planted-G3-01' / 'holdout-planted-G3-01' -> 'G3'."""
    m = re.search(r"-planted-(G[1-8])-", case_id)
    if not m:
        raise ValueError(f"not a planted case id: {case_id}")
    return m.group(1)


def _matches(finding: dict[str, Any], item: dict[str, str]) -> bool:
    return (finding["class"] == item["class"] and finding["file"] == item["file"]
            and finding["component"]["name"] == item["component"])


# ------------------------------------------------------------------ GrantLock --

def score_grantlock(corpus: str | os.PathLike[str], checker: Callable[[Path], dict[str, Any]] | None = None) -> dict[str, Any]:
    corpus = Path(corpus)
    checker = checker or (lambda repo: check(repo))
    cases = _load_cases(corpus)
    case_hits = {c: [0, 0] for c in CLASSES}   # strict case-level: [detected, total]
    item_hits = {c: [0, 0] for c in CLASSES}
    misses: list[dict[str, Any]] = []
    extra_on_planted: dict[str, int] = {c: 0 for c in CLASSES}
    clean_total = clean_fp = 0
    fp_details: list[dict[str, Any]] = []
    diff_total = diff_ok = 0
    diff_details: list[dict[str, Any]] = []

    for case in cases:
        cid = case["case_id"]
        root = corpus / "cases" / cid
        if case["kind"] == "planted":
            findings = checker(root / "repo")["findings"]
            target = target_class(cid)
            items = [p for p in case["planted"] if p["class"] == target]
            all_hit = True
            for it in items:
                hit = any(_matches(f, it) for f in findings)
                item_hits[target][1] += 1
                item_hits[target][0] += int(hit)
                if not hit:
                    all_hit = False
                    misses.append({"case_id": cid, "variant": case.get("variant"), "class": target, "file": it["file"],
                                   "component": it["component"],
                                   "classes_reported_for_file": sorted({f["class"] for f in findings if f["file"] == it["file"]})})
            case_hits[target][1] += 1
            case_hits[target][0] += int(all_hit and bool(items))
            for c in {f["class"] for f in findings} - {target}:
                extra_on_planted[c] += 1
        elif case["kind"] == "clean":
            res = checker(root / "repo")
            clean_total += 1
            if res["findings"]:
                clean_fp += 1
                fp_details.append({"case_id": cid, "classes": sorted({f["class"] for f in res["findings"]}),
                                   "finding_ids": sorted(f["finding_id"] for f in res["findings"])[:10]})
        elif case["kind"] == "diff_pair":
            res = checker(root / "after")
            predicted = sorted({f["class"] for f in res["findings"]})
            ok = predicted == case["expected_labels"]
            diff_total += 1
            diff_ok += int(ok)
            diff_details.append({"case_id": cid, "variant": case.get("variant"), "expected": case["expected_labels"],
                                 "predicted": predicted, "correct": ok})

    return {
        "recall_by_class": {c: {"detected": case_hits[c][0], "total": case_hits[c][1], "recall": _ratio(*case_hits[c])} for c in CLASSES},
        "item_recall_by_class": {c: {"detected": item_hits[c][0], "total": item_hits[c][1], "recall": _ratio(*item_hits[c])} for c in CLASSES},
        "planted_misses": misses,
        "other_classes_on_planted_cases": extra_on_planted,
        "clean": {"cases": clean_total, "fp_cases": clean_fp, "fp_rate": _ratio(clean_fp, clean_total), "fp_details": fp_details},
        "diff_pair": {"cases": diff_total, "correct": diff_ok, "accuracy": _ratio(diff_ok, diff_total), "details": diff_details},
    }


# ------------------------------------------------------------------ baselines --

def parse_gitleaks_report(data: Any, root: Path) -> list[dict[str, str]]:
    """Keep only (file, rule). Secret / Match / Fingerprint fields are dropped."""
    pairs = set()
    for item in data or []:
        f = str(item.get("File", ""))
        rel = os.path.relpath(f, root) if os.path.isabs(f) else f
        pairs.add((Path(rel).as_posix(), str(item.get("RuleID", ""))))
    return [{"file": a, "rule": b} for a, b in sorted(pairs)]


def parse_trufflehog_lines(text: str, root: Path) -> list[dict[str, str]]:
    """Keep only (file, detector). Raw / RawV2 / Redacted are dropped."""
    pairs = set()
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        f = (((obj.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}).get("file")
        if not f:
            continue
        rel = os.path.relpath(f, root) if os.path.isabs(f) else f
        pairs.add((Path(rel).as_posix(), str(obj.get("DetectorName", ""))))
    return [{"file": a, "rule": b} for a, b in sorted(pairs)]


def run_gitleaks(exe: str, target: Path) -> list[dict[str, str]]:
    with tempfile.TemporaryDirectory() as td:
        report = Path(td) / "report.json"
        cmd = [exe, "detect", "--no-git", "--no-banner", "--redact", "--exit-code", "0",
               "--source", str(target.resolve()), "--report-format", "json", "--report-path", str(report)]
        subprocess.run(cmd, check=False, capture_output=True, timeout=300)
        data = json.loads(report.read_text()) if report.is_file() and report.stat().st_size else []
        return parse_gitleaks_report(data, target.resolve())


def run_trufflehog(exe: str, target: Path) -> list[dict[str, str]]:
    # --no-verification: never contact providers. --no-update: no self-update check.
    cmd = [exe, "filesystem", str(target.resolve()), "--json", "--no-verification", "--no-update"]
    proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=300)
    return parse_trufflehog_lines(proc.stdout, target.resolve())


BASELINES = {"gitleaks": run_gitleaks, "trufflehog": run_trufflehog}


def score_baseline(name: str, corpus: str | os.PathLike[str], which: Callable[[str], str | None] = shutil.which,
                   runner: Callable[[str, Path], list[dict[str, str]]] | None = None) -> dict[str, Any]:
    corpus = Path(corpus)
    exe = which(name)
    if exe is None:
        return {"status": NOT_RUN, "reason": f"`{name}` not found on PATH (not installed locally; Phase 1 does not install tools)",
                "recall_by_class": {c: NOT_RUN for c in CLASSES}, "clean": NOT_RUN, "diff_pair": NOT_RUN}
    runner = runner or BASELINES[name]
    cases = _load_cases(corpus)
    hits = {c: [0, 0] for c in CLASSES}
    clean_total = clean_fp = 0
    try:
        for case in cases:
            root = corpus / "cases" / case["case_id"]
            if case["kind"] == "planted":
                target = target_class(case["case_id"])
                found = runner(exe, root / "repo")
                files = {x["file"] for x in found}
                hits[target][1] += 1
                if target == "G1":  # structural: a value scanner can only see G1
                    items = [p for p in case["planted"] if p["class"] == "G1"]
                    hits[target][0] += int(bool(items) and all(p["file"] in files for p in items))
            elif case["kind"] == "clean":
                clean_total += 1
                clean_fp += int(bool(runner(exe, root / "repo")))
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        return {"status": NOT_RUN, "reason": f"`{name}` failed to run: {exc.__class__.__name__}",
                "recall_by_class": {c: NOT_RUN for c in CLASSES}, "clean": NOT_RUN, "diff_pair": NOT_RUN}
    return {
        "status": "ok",
        "reason": None,
        "recall_by_class": {c: {"detected": hits[c][0], "total": hits[c][1], "recall": _ratio(*hits[c]),
                                "note": None if c == "G1" else "structurally invisible to value scanners (recorded as 0)"}
                            for c in CLASSES},
        "clean": {"cases": clean_total, "fp_cases": clean_fp, "fp_rate": _ratio(clean_fp, clean_total)},
        "diff_pair": "N/A (value scanners do not classify grant changes)",
    }


# ------------------------------------------------------------------ report --

def score_all(corpus: str | os.PathLike[str], which: Callable[[str], str | None] = shutil.which) -> dict[str, Any]:
    corpus = Path(corpus)
    manifest = json.loads((corpus / "manifest.json").read_text())
    gl = score_grantlock(corpus)
    headline = {c: gl["recall_by_class"][c]["recall"] for c in VALUE_FREE_HEADLINE}
    return {
        "schema_version": "1.0",
        "document": "grantbench.scores",
        "split": manifest["split"],
        "corpus_sha256": manifest["corpus_sha256"],
        "grantlock": gl,
        "baselines": {name: score_baseline(name, corpus, which=which) for name in sorted(BASELINES)},
        "headline": {
            "value_free_recall": headline,
            "value_free_recall_min": min((v for v in headline.values() if v is not None), default=None),
            "clean_fp_rate": gl["clean"]["fp_rate"],
            "criterion_5_pass": all(v is not None and v >= 0.8 for v in headline.values())
            and gl["clean"]["fp_rate"] is not None and gl["clean"]["fp_rate"] <= 0.05,
        },
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="grantbench.score")
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    res = score_all(args.corpus)
    text = json.dumps(res, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
    print(json.dumps(res["headline"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
