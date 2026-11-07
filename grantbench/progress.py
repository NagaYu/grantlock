"""Snapshot of the regression numbers used by the Phase 2 fix round (numbers only).

    python -m grantbench.progress --out reports/phase2-fix-<label>.json

frozen dev (bench/dev-frozen), dev-ext (regenerated from its seed into a temp dir),
and the disclosed holdout at ~/grantlock-holdout (read-only). The output holds
aggregate numbers only - no case ids, paths or contents.
"""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .generator import corpus_digest, generate_ext
from .holdout_score import holdout_digest
from .lockless import score_lockless
from .score import score_grantlock

ROOT = Path(__file__).resolve().parents[1]


def _nums(r):
    return {"recall": {c: [v["detected"], v["total"]] for c, v in r["recall_by_class"].items()},
            "clean": [r["clean"]["fp_cases"], r["clean"]["cases"]],
            "diff": [r["diff_pair"]["correct"], r["diff_pair"]["cases"]]}


def snapshot(holdout: Path | None) -> dict:
    out = {"frozen_dev": dict(_nums(score_grantlock(ROOT / "bench" / "dev-frozen")),
                              sha256=corpus_digest(ROOT / "bench" / "dev-frozen"))}
    with tempfile.TemporaryDirectory() as td:
        m = generate_ext(Path(td) / "ext")
        out["dev_ext"] = dict(_nums(score_lockless(Path(td) / "ext")), sha256=m["corpus_sha256"])
    if holdout is not None and (holdout / "manifest.json").is_file():
        r = score_lockless(holdout)
        out["holdout_disclosed"] = dict(_nums(r), sha256=holdout_digest(holdout),
                                        recall_by_surface=r["recall_by_surface"],
                                        excluded_out_of_scope=len(r["excluded_out_of_scope"]))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="grantbench.progress")
    ap.add_argument("--out", required=True)
    ap.add_argument("--holdout", default="~/grantlock-holdout")
    a = ap.parse_args(argv)
    res = snapshot(Path(a.holdout).expanduser())
    Path(a.out).write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    for k, v in res.items():
        print(k, {c: f"{d}/{t}" for c, (d, t) in v["recall"].items()}, "clean", v["clean"], "diff", v["diff"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
