"""scan(repo_path) -> inventory. Reads files only; no network, no writes."""

from __future__ import annotations

import json
import os
import posixpath
from pathlib import Path
from typing import Any

from . import model, owners, schemas
from .parsers import compose, dotenv, gha, k8s, mcp, terraform
from .parsers.common import load_jsonc

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", "vendor",
             ".tox", ".mypy_cache", ".pytest_cache", "target", ".next", ".terraform"}
SKIP_JSON = {"package-lock.json", "grantlock.json", "grantlock.policy.json", "composer.lock"}
MAX_BYTES = 2 * 1024 * 1024
POLICY_FILE = "grantlock.policy.json"


def _iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d)))
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            yield rel, full


def _read(full: str) -> str | None:
    try:
        if os.path.getsize(full) > MAX_BYTES:
            return None
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def is_workflow(rel: str) -> bool:
    d, base = posixpath.split(rel)
    return d == ".github/workflows" and base.endswith((".yml", ".yaml"))


def _load_declared_owners(root: Path) -> dict[str, list[str]]:
    p = root / POLICY_FILE
    if not p.is_file():
        return {}
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    d = doc.get("declared_owners") if isinstance(doc, dict) else None
    return {k: list(v) for k, v in d.items() if isinstance(v, list) and v} if isinstance(d, dict) else {}


def _codeowners(root: Path) -> list[owners.Rule]:
    for loc in owners.CODEOWNERS_LOCATIONS:
        p = root / loc
        if p.is_file() and not p.is_symlink():
            return owners.parse_codeowners(p.read_text(encoding="utf-8", errors="replace"), loc)
    return []


def scan(repo_path: str | os.PathLike[str]) -> dict[str, Any]:
    root = Path(repo_path)
    if not root.is_dir():
        raise NotADirectoryError(str(repo_path))
    entries: list[dict[str, Any]] = []
    warnings: list[dict[str, str]] = []
    k8s_objects: list[dict[str, Any]] = []
    tf_blocks: list[Any] = []
    for rel, full in _iter_files(root):
        base = posixpath.basename(rel)
        if is_workflow(rel):
            text = _read(full)
            if text is not None:
                e, w = gha.parse_workflow(rel, text)
                entries += e
                warnings += w
        elif dotenv.is_env_file(rel):
            text = _read(full)
            if text is not None:
                e, w = dotenv.parse_env(rel, text)
                entries += e
                warnings += w
        elif base.endswith(".json") and base not in SKIP_JSON:
            text = _read(full)
            if text is None:
                continue
            try:
                doc = load_jsonc(text)
            except ValueError:
                if "mcp" in base.lower():
                    warnings.append({"file": rel, "message": "invalid JSON in MCP-like config"})
                continue
            if mcp.is_mcp_config(rel, doc):
                e, w = mcp.parse_mcp(rel, text)
                entries += e
                warnings += w
        elif compose.is_compose_file(rel):
            text = _read(full)
            if text is not None:
                e, w = compose.parse_compose(rel, text)
                entries += e
                warnings += w
        elif base.endswith((".yaml", ".yml")):
            text = _read(full)
            if text is not None:
                o, w = k8s.load_objects(rel, text)
                k8s_objects += o
                warnings += w
        elif base.endswith(".tf"):
            text = _read(full)
            if text is not None:
                b, w = terraform.load_blocks(rel, text)
                tf_blocks += b
                warnings += w
    for builder, items in ((k8s.build, k8s_objects), (terraform.build, tf_blocks)):
        if items:
            e, w = builder(items)
            entries += e
            warnings += w
    rules = _codeowners(root)
    declared = _load_declared_owners(root)
    for e in entries:
        cid = e["component"]["id"]
        if cid in declared:
            e["owner"] = owners.declared_record(declared[cid], cid)
        else:
            e["owner"] = owners.owner_record(rules, e["component"]["file"])
    entries.sort(key=lambda x: (x["identity_id"], x["component"]["id"]))
    inv = {
        "schema_version": schemas.SCHEMA_VERSION,
        "document": schemas.DOC_INVENTORY,
        "generator": dict(model.GENERATOR),
        "entries": entries,
        "warnings": sorted(warnings, key=lambda w: (w["file"], w["message"])),
    }
    schemas.validate(inv, schemas.DOC_INVENTORY)
    return inv
