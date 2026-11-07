"""GrantBench corpus generator.

    python -m grantbench.generator --split dev --out bench/dev

dev   = 80 planted (G1-G8 x 10) + 24 clean + 16 diff_pair = 120 cases, seed-fixed.
holdout is implemented but refused unless the output directory is outside this
repository AND GRANTLOCK_ALLOW_HOLDOUT=1 (Phase 1 never generates it).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator

import grantlock
from grantlock import lockfile

from .mutations import DIFF_PAIRS, PLANTED, Sink, requirements
from .templates import add_near_misses, clone, make_base, render

REPO_ROOT = Path(__file__).resolve().parents[1]
SEEDS = {"dev": 20261107, "holdout": 90210417, "dev-ext": 20261121}
CLASSES = ["G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8"]
PLANTED_PER_CLASS = 10
N_CLEAN = 24
N_DIFF = 16
MANIFEST = "manifest.json"

CASE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "document", "case_id", "split", "kind", "lang", "planted", "expected_labels", "description"],
    "properties": {
        "schema_version": {"const": "1.0"},
        "document": {"const": "grantbench.case"},
        "case_id": {"type": "string", "pattern": "^(dev|dev-ext|holdout)-(planted-G[1-8]|clean|diff)-[0-9]{2}$"},
        "split": {"enum": ["dev", "dev-ext", "holdout"]},
        "kind": {"enum": ["planted", "clean", "diff_pair"]},
        "lang": {"enum": ["en", "ja"]},
        "variant": {"type": "string"},
        "planted": {"type": "array", "items": {
            "type": "object", "additionalProperties": False, "required": ["class", "file", "component", "note"],
            "properties": {"class": {"enum": CLASSES}, "file": {"type": "string"}, "component": {"type": "string"},
                           "note": {"type": "string", "maxLength": 200}}}},
        "expected_labels": {"type": "array", "items": {"enum": CLASSES}, "uniqueItems": True},
        "description": {"type": "string", "maxLength": 400},
    },
    "allOf": [
        {"if": {"properties": {"kind": {"const": "planted"}}}, "then": {"properties": {"planted": {"minItems": 1}}}},
        {"if": {"properties": {"kind": {"const": "clean"}}},
         "then": {"properties": {"planted": {"maxItems": 0}, "expected_labels": {"maxItems": 0}}}},
    ],
}
_CASE_VALIDATOR = Draft202012Validator(CASE_SCHEMA)

DESCRIPTIONS = {
    ("planted", "en"): "Snapshot of {p} with one planted {c} risk on top of a reviewed grantlock.json.",
    ("planted", "ja"): "{p} のスナップショット。レビュー済み grantlock.json の上に {c} のリスクを仕込んである。",
    ("clean", "en"): "Snapshot of {p}: least-privilege, fully declared, lockfile in sync.",
    ("clean", "ja"): "{p} のスナップショット。最小権限・宣言済みでロックファイルと一致している。",
    ("diff_pair", "en"): "Before/after pair for {p}; after/grantlock.json is the lock committed for before/.",
    ("diff_pair", "ja"): "{p} の変更前後ペア。after/grantlock.json は before/ のときにコミットされたロック。",
}


class HoldoutRefused(PermissionError):
    pass


def check_holdout_allowed(out_dir: str | os.PathLike[str], env: Mapping[str, str] | None = None) -> None:
    """Raise HoldoutRefused unless out_dir is outside this repo and the env opt-in is set."""
    env = os.environ if env is None else env
    out = Path(out_dir).resolve()
    if env.get("GRANTLOCK_ALLOW_HOLDOUT") != "1":
        raise HoldoutRefused("holdout generation refused: set GRANTLOCK_ALLOW_HOLDOUT=1 explicitly")
    if out == REPO_ROOT or REPO_ROOT in out.parents:
        raise HoldoutRefused(f"holdout generation refused: output must be outside the repository ({REPO_ROOT.name})")


def validate_case(doc: dict[str, Any]) -> list[str]:
    return [e.message for e in _CASE_VALIDATOR.iter_errors(doc)]


def _write_tree(root: Path, files: dict[str, str]) -> None:
    if root.exists():
        shutil.rmtree(root)
    for rel in sorted(files):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(files[rel])


def _lock_text(root: Path) -> str:
    return lockfile.dumps(grantlock.lock(grantlock.scan(root)))


def corpus_digest(out: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(out.rglob("*")):
        if p.is_file() and p != out / MANIFEST:
            rel = p.relative_to(out).as_posix()
            h.update(rel.encode() + b"\0" + p.read_bytes() + b"\0")
    return h.hexdigest()


def _prepare_out(out: Path, force: bool) -> None:
    if out.exists() and any(out.iterdir()):
        if not force:
            raise FileExistsError(f"{out} is not empty (use --force to regenerate)")
        if not (out / MANIFEST).is_file():
            raise FileExistsError(f"refusing to clear {out}: it does not look like a GrantBench corpus")
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)


def _base(rng: random.Random, lang: str, req: set[str]) -> dict[str, Any]:
    spec = make_base(rng, lang, req)
    add_near_misses(spec, rng)
    return spec


def _case_doc(case_id, split, kind, lang, planted, labels, project, variant) -> dict[str, Any]:
    c = ",".join(sorted({p["class"] for p in planted})) if planted else ""
    doc = {
        "schema_version": "1.0", "document": "grantbench.case", "case_id": case_id, "split": split,
        "kind": kind, "lang": lang, "variant": variant, "planted": planted, "expected_labels": labels,
        "description": DESCRIPTIONS[(kind, lang)].format(p=project, c=c),
    }
    errs = validate_case(doc)
    if errs:
        raise ValueError(f"{case_id}: invalid case: {errs[:3]}")
    return doc


def generate(split: str, out_dir: str | os.PathLike[str], *, force: bool = False,
             sink: Sink | None = None) -> dict[str, Any]:
    if split == "holdout":
        check_holdout_allowed(out_dir)
    elif split != "dev":
        raise ValueError(f"unknown split {split!r}")
    seed = SEEDS[split]
    sink = sink if sink is not None else Sink()
    out = Path(out_dir)
    _prepare_out(out, force)
    cases_dir = out / "cases"
    index: list[dict[str, str]] = []

    def rng_for(case_id: str) -> random.Random:
        return random.Random(f"{seed}:{case_id}")

    # planted -----------------------------------------------------------------
    for cls in CLASSES:
        variants = PLANTED[cls]
        for i in range(PLANTED_PER_CLASS):
            case_id = f"{split}-planted-{cls}-{i + 1:02d}"
            rng = rng_for(case_id)
            variant = variants[i % len(variants)]
            lang = "ja" if i % 2 else "en"
            base = _base(rng, lang, requirements(variant))
            mutated = clone(base)
            planted = variant(mutated, rng, sink)
            repo = cases_dir / case_id / "repo"
            _write_tree(repo, render(base))
            lock_text = _lock_text(repo)
            files = render(mutated)
            files["grantlock.json"] = lock_text
            _write_tree(repo, files)
            doc = _case_doc(case_id, split, "planted", lang, planted, [], base["ctx"]["project"], variant.__name__)
            (cases_dir / case_id / "case.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            index.append({"case_id": case_id, "kind": "planted"})

    # clean -------------------------------------------------------------------
    clean_reqs = [set(), {"vscode"}, {"deploy_aws"}, {"deploy_gcp"}, {"deploy_azure"}, {"release_pypi"},
                  {"eval", "docker"}, {"remote_oauth", "codecov"}]
    for i in range(N_CLEAN):
        case_id = f"{split}-clean-{i + 1:02d}"
        rng = rng_for(case_id)
        lang = "ja" if i % 2 else "en"
        base = _base(rng, lang, clean_reqs[i % len(clean_reqs)])
        repo = cases_dir / case_id / "repo"
        _write_tree(repo, render(base))
        (repo / "grantlock.json").write_text(_lock_text(repo), encoding="utf-8")
        doc = _case_doc(case_id, split, "clean", lang, [], [], base["ctx"]["project"], "clean")
        (cases_dir / case_id / "case.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        index.append({"case_id": case_id, "kind": "clean"})

    # diff pairs --------------------------------------------------------------
    for i in range(N_DIFF):
        case_id = f"{split}-diff-{i + 1:02d}"
        rng = rng_for(case_id)
        variant, labels = DIFF_PAIRS[i % len(DIFF_PAIRS)]
        lang = "ja" if i % 2 else "en"
        base = _base(rng, lang, requirements(variant))
        mutated = clone(base)
        planted = variant(mutated, rng, sink)
        before = cases_dir / case_id / "before"
        _write_tree(before, render(base))
        lock_text = _lock_text(before)
        (before / "grantlock.json").write_text(lock_text, encoding="utf-8")
        files = render(mutated)
        files["grantlock.json"] = lock_text
        _write_tree(cases_dir / case_id / "after", files)
        doc = _case_doc(case_id, split, "diff_pair", lang, planted, sorted(labels), base["ctx"]["project"], variant.__name__)
        (cases_dir / case_id / "case.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        index.append({"case_id": case_id, "kind": "diff_pair"})

    by_class = {c: sum(1 for x in index if x["case_id"].startswith(f"{split}-planted-{c}-")) for c in CLASSES}
    manifest = {
        "schema_version": "1.0",
        "document": "grantbench.manifest",
        "split": split,
        "seed": seed,
        "counts": {"planted": sum(by_class.values()), "clean": N_CLEAN, "diff_pair": N_DIFF,
                   "total": len(index), "planted_by_class": by_class},
        "cases": index,
        "corpus_sha256": corpus_digest(out),
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def generate_ext(out_dir: str | os.PathLike[str], *, force: bool = False, record: list[str] | None = None) -> dict[str, Any]:
    """dev-ext: compose / Kubernetes / Terraform cases in the lockfile-less layout (base/repo, before/after)."""
    from .ext_mutations import EXT_DIFF_PAIRS, EXT_PLANTED
    from .ext_templates import add_ext_near_misses, clone_ext, make_ext_base, render_ext

    split, seed = "dev-ext", SEEDS["dev-ext"]
    out = Path(out_dir)
    _prepare_out(out, force)
    values = record if record is not None else []

    def sink(v: str) -> str:
        values.append(v)
        return v

    index: list[dict[str, str]] = []
    surfaces: dict[str, dict[str, int]] = {}

    def base_for(case_id: str, i: int, req: set[str]):
        rng = random.Random(f"{seed}:{case_id}")
        lang = "ja" if i % 3 == 1 else "en"
        spec = make_ext_base(rng, lang, req)
        add_ext_near_misses(spec, rng)
        return rng, lang, spec

    def write_case(case_id, kind, lang, planted, labels, project, variant_name, trees):
        root = out / "cases" / case_id
        for sub, files in trees.items():
            _write_tree(root / sub, files)
        doc = _case_doc(case_id, split, kind, lang, planted, labels, project, variant_name)
        (root / "case.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        index.append({"case_id": case_id, "kind": kind})

    for cls, variants in EXT_PLANTED.items():
        for i, var in enumerate(variants):
            case_id = f"{split}-planted-{cls}-{i + 1:02d}"
            rng, lang, base = base_for(case_id, i, var.requires)
            mutated = clone_ext(base)
            planted = var(mutated, rng, sink)
            before, after = render_ext(base), render_ext(mutated)
            if before == after:
                raise ValueError(f"{case_id}: mutation {var.__name__} had no effect")
            write_case(case_id, "planted", lang, planted, [], base["project"], var.__name__, {"base": before, "repo": after})
            surfaces.setdefault(var.surface, {}).setdefault(cls, 0)
            surfaces[var.surface][cls] += 1
    for i in range(12):
        case_id = f"{split}-clean-{i + 1:02d}"
        _, lang, base = base_for(case_id, i, {"aws" if i % 2 == 0 else "gcp"})
        write_case(case_id, "clean", lang, [], [], base["project"], "clean", {"repo": render_ext(base)})
    for i, (var, labels) in enumerate(EXT_DIFF_PAIRS):
        case_id = f"{split}-diff-{i + 1:02d}"
        rng, lang, base = base_for(case_id, i, var.requires)
        mutated = clone_ext(base)
        planted = var(mutated, rng, sink)
        write_case(case_id, "diff_pair", lang, planted, sorted(labels), base["project"], var.__name__,
                   {"before": render_ext(base), "after": render_ext(mutated)})

    by_class = {c: sum(1 for x in index if f"-planted-{c}-" in x["case_id"]) for c in CLASSES}
    manifest = {
        "schema_version": "1.0", "document": "grantbench.manifest", "split": split, "seed": seed,
        "counts": {"planted": sum(by_class.values()), "clean": 12, "diff_pair": len(EXT_DIFF_PAIRS),
                   "total": len(index), "planted_by_class": by_class},
        "planted_by_surface": surfaces,
        "cases": index,
        "corpus_sha256": corpus_digest(out),
    }
    (out / MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="grantbench.generator")
    ap.add_argument("--split", choices=["dev", "dev-ext", "holdout"], default="dev")
    ap.add_argument("--out", required=True)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args(argv)
    try:
        m = generate_ext(args.out, force=args.force) if args.split == "dev-ext" else generate(args.split, args.out, force=args.force)
    except (HoldoutRefused, FileExistsError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"split": m["split"], "total": m["counts"]["total"], "corpus_sha256": m["corpus_sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
