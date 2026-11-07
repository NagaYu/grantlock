"""Real-repository false-positive probe (Phase 2 Step 7).

Network use is confined to `clone()` here (shallow git clone into a directory
outside this repository). Scanning uses the offline core only.

    python -m grantbench.probe --workdir <outside-repo dir> --out reports/phase2_probe.json
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

import grantlock
from grantlock.inventory import SKIP_JSON, _iter_files, _read, is_workflow
from grantlock.parsers import compose, dotenv, k8s, mcp
from grantlock.parsers.common import load_jsonc

REPOS = ["NagaYu/caplock", "modelcontextprotocol/servers", "github/github-mcp-server"]
REPO_ROOT = Path(__file__).resolve().parents[1]


def clone(slug: str, workdir: Path) -> Path:
    dest = workdir / slug.replace("/", "_")
    if REPO_ROOT == dest.resolve() or REPO_ROOT in dest.resolve().parents:
        raise ValueError("probe clones must live outside the GrantLock repository")
    if not dest.exists():
        subprocess.run(["git", "clone", "--quiet", "--depth", "1", f"https://github.com/{slug}", str(dest)], check=True)
    return dest


def surface_files(root: Path) -> dict[str, Any]:
    """Which files each surface looked at, and which yielded entries; plus config examples we do not read."""
    cand: dict[str, list[str]] = {s: [] for s in ("mcp", "gha", "env", "compose", "k8s", "terraform")}
    md_examples = 0
    for rel, full in _iter_files(root):
        base = posixpath.basename(rel)
        if is_workflow(rel):
            cand["gha"].append(rel)
        elif dotenv.is_env_file(rel):
            cand["env"].append(rel)
        elif base.endswith(".json") and base not in SKIP_JSON:
            text = _read(full)
            try:
                if text is not None and mcp.is_mcp_config(rel, load_jsonc(text)):
                    cand["mcp"].append(rel)
            except ValueError:
                pass
        elif compose.is_compose_file(rel):
            cand["compose"].append(rel)
        elif base.endswith((".yaml", ".yml")):
            text = _read(full)
            if text is not None and k8s.looks_like_k8s(text):
                cand["k8s"].append(rel)
        elif base.endswith(".tf"):
            cand["terraform"].append(rel)
        elif base.lower().endswith((".md", ".mdx")):
            text = _read(full) or ""
            if '"mcpServers"' in text or '"servers"' in text and "mcp" in text.lower():
                md_examples += 1
    return {"candidates": {k: len(v) for k, v in cand.items()}, "candidate_files": cand,
            "markdown_files_with_unscanned_mcp_examples": md_examples}


_KIND_SURFACE = {"mcp_server": "mcp", "gha_workflow": "gha", "env_decl": "env", "env_use": "env", "compose_service": "compose",
                 "k8s_workload": "k8s", "k8s_service_account": "k8s", "k8s_secret": "k8s", "k8s_rbac": "k8s",
                 "terraform": "terraform", "terraform_workload": "terraform"}


def probe(root: Path) -> dict[str, Any]:
    inv = grantlock.scan(root)
    f = grantlock.diff(inv, grantlock.lock(inv))
    files = surface_files(root)
    files_with_entries = Counter()
    for s, fs in Counter((_KIND_SURFACE[e["component"]["kind"]], e["component"]["file"]) for e in inv["entries"]).items():
        files_with_entries[s[0]] += 1
    return {
        "surfaces": {s: {"files_considered": files["candidates"][s], "files_with_identities": files_with_entries.get(s, 0),
                         "bindings": sum(1 for e in inv["entries"] if _KIND_SURFACE[e["component"]["kind"]] == s),
                         "findings": sum(1 for x in f["findings"] if _KIND_SURFACE[x["component"]["kind"]] == s)}
                     for s in files["candidates"]},
        "markdown_files_with_unscanned_mcp_examples": files["markdown_files_with_unscanned_mcp_examples"],
        "warnings": inv["warnings"],
        "findings": [{"finding_id": x["finding_id"], "class": x["class"], "severity": x["severity"], "file": x["file"],
                      "line": x["line"], "component": x["component"]["name"], "identity_id": x["identity_id"],
                      "message": x["message"]} for x in f["findings"]],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="grantbench.probe")
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--out")
    args = ap.parse_args(argv)
    wd = Path(args.workdir)
    wd.mkdir(parents=True, exist_ok=True)
    res = {}
    for slug in REPOS:
        d = clone(slug, wd)
        head = subprocess.run(["git", "-C", str(d), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        res[slug] = dict(probe(d), commit=head)
    text = json.dumps(res, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    for slug, r in res.items():
        print(slug, {s: v for s, v in r["surfaces"].items() if v["files_considered"]}, "findings:", len(r["findings"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
