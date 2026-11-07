"""Score the sealed holdout corpus (Phase 2 Step 8). Read-only; numbers only.

    python -m grantbench.holdout_score --corpus ~/grantlock-holdout --out reports/phase2_holdout_scores.json

The output contains aggregate numbers only (no case ids, paths, components or
case text), so the report cannot leak the sealed corpus.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from .lockless import score_lockless
from .score import BASELINES, CLASSES, NOT_RUN, score_baseline

HEADLINE = ["G2", "G3", "G7"]


def holdout_digest(corpus: Path) -> str:
    """corpus_sha256 exactly as defined in the holdout brief: files under cases/, sorted by POSIX
    relative-path string (byte order), each fed as path-utf8 + 0x00 + raw bytes + 0x00."""
    files = sorted((p.relative_to(corpus).as_posix(), p) for p in (corpus / "cases").rglob("*") if p.is_file())
    h = hashlib.sha256()
    for rel, p in sorted(files, key=lambda t: t[0].encode("utf-8")):
        h.update(rel.encode("utf-8") + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def _numbers(res: dict[str, Any]) -> dict[str, Any]:
    return {
        "recall_by_class": {c: {k: v[k] for k in ("detected", "total", "recall")} for c, v in res["recall_by_class"].items()},
        "clean": {k: res["clean"][k] for k in ("cases", "fp_cases", "fp_rate")},
        "diff_pair": {k: res["diff_pair"][k] for k in ("cases", "correct", "accuracy")},
    }


def gate(strict: dict[str, Any]) -> dict[str, Any]:
    rec = {c: strict["recall_by_class"][c]["recall"] for c in HEADLINE}
    vals = [v for v in rec.values() if v is not None]
    avg = round(sum(vals) / len(vals), 4) if len(vals) == len(HEADLINE) else None
    fp = strict["clean"]["fp_rate"]
    ok = (len(vals) == len(HEADLINE) and all(v >= 0.8 for v in vals) and avg is not None and avg >= 0.9
          and fp is not None and fp <= 0.05)
    return {"headline_recall": rec, "headline_average": avg, "clean_fp_rate": fp, "criterion_4_pass": ok}


def score_holdout(corpus: str | Path, which=shutil.which) -> dict[str, Any]:
    corpus = Path(corpus).expanduser()
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    digest = holdout_digest(corpus)
    strict = score_lockless(corpus)
    fb = score_lockless(corpus, fallback_new_surfaces=True)
    base = {}
    for name in sorted(BASELINES):
        b = score_baseline(name, corpus, which=which)
        base[name] = b if b["status"] == NOT_RUN else {
            "status": b["status"],
            "recall_by_class": {c: {k: b["recall_by_class"][c][k] for k in ("detected", "total", "recall")} for c in CLASSES},
            "clean": b["clean"]}
    excluded = len(strict["excluded_out_of_scope"])
    return {
        "schema_version": "1.0",
        "document": "grantbench.holdout_scores",
        "corpus_sha256_manifest": manifest.get("corpus_sha256"),
        "corpus_sha256_recomputed": digest,
        "hash_match": manifest.get("corpus_sha256") == digest,
        "counts": {"excluded_out_of_scope_items": excluded,
                   "excluded_by_surface": _count(strict["excluded_out_of_scope"], "surface"),
                   "fallback_matches": len(fb["fallback_matches"]),
                   "detector_errors_by_kind": _count(strict["errors"], "kind"),
                   "detector_error_types": sorted({e["error"] for e in strict["errors"]})},
        "strict": _numbers(strict),
        "with_fallback_new_surfaces": _numbers(fb),
        "gate_strict": gate(_numbers(strict)),
        "gate_with_fallback": gate(_numbers(fb)),
        "recall_by_surface_strict": strict["recall_by_surface"],
        "diff_mismatch_patterns": sorted({(tuple(d["expected"]), tuple(d["predicted"])) for d in strict["diff_pair"]["details"]
                                          if not d["correct"]}),
        "baselines": base,
    }


def _count(items, key):
    out: dict[str, int] = {}
    for it in items:
        out[it[key]] = out.get(it[key], 0) + 1
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="grantbench.holdout_score")
    ap.add_argument("--corpus", default="~/grantlock-holdout")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    corpus = Path(args.corpus).expanduser()
    if not (corpus / "manifest.json").is_file():
        print(f"NOT RUN: no sealed holdout corpus at {corpus}")
        return 3
    res = score_holdout(corpus)
    Path(args.out).write_text(json.dumps(res, indent=2, default=list) + "\n", encoding="utf-8")
    print(json.dumps({"hash_match": res["hash_match"], "gate_strict": res["gate_strict"]}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
