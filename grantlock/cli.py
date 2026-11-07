"""Thin CLI over the core. No logic beyond argument parsing, file I/O and formatting.

    grantlock scan  [--repo DIR] [--output FILE]
    grantlock lock  [--repo DIR] [--lockfile FILE]
    grantlock check [--repo DIR] [--lockfile FILE] [--policy FILE] [--format text|json|sarif] [--output FILE]
    grantlock evidence [--repo DIR] [--lockfile FILE] [--policy FILE] [--previous-lock FILE] --output-dir DIR

check exit codes: 0 = no critical finding, 1 = critical finding, 2 = usage/input error.
check never writes grantlock.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import __version__, lockfile, policy as policy_mod
from .check import MissingLockfile, check, evidence
from .inventory import scan
from .sarif import to_sarif
from .schemas import SchemaError


def _write_or_print(text: str, output: str | None) -> None:
    if output:
        with open(output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)


def _format_text(f: dict[str, Any]) -> str:
    lines = []
    for x in f["findings"]:
        loc = f"{x['file']}:{x['line']}" if x["line"] else x["file"]
        lines.append(f"{x['severity'].upper():8} {x['class']} [{x['change']}] {loc} ({x['component']['name']}): {x['message']}")
        if x["production"]["value"]:
            lines.append(f"{'':8}    production: {'; '.join(x['production']['evidence'])}")
    s = f["summary"]
    lines.append(f"grantlock check: {s['critical']} critical, {s['warning']} warning, {s['note']} note"
                 f"; lockfile {'in sync' if s['lock_in_sync'] else 'out of date (run `grantlock lock` to accept changes)'}")
    if f["drift"]:
        lines.append(f"unclassified drift: {len(f['drift'])} change(s) (see --format json)")
    return "\n".join(lines) + "\n"


def cmd_scan(args) -> int:
    inv = scan(args.repo)
    _write_or_print(json.dumps(inv, indent=2, sort_keys=True, ensure_ascii=False) + "\n", args.output)
    return 0


def cmd_lock(args) -> int:
    path = args.lockfile or os.path.join(args.repo, lockfile.LOCK_FILENAME)
    doc = lockfile.lock(scan(args.repo))
    new_text = lockfile.dumps(doc)
    old_text = None
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            old_text = fh.read()
    if old_text == new_text:
        print(f"{os.path.basename(path)} is up to date ({len(doc['entries'])} entries)")
        return 0
    lockfile.write(path, doc)
    print(f"wrote {os.path.basename(path)} ({len(doc['entries'])} entries); review and commit the diff")
    return 0


def cmd_check(args) -> int:
    f = check(args.repo, args.lockfile, args.policy)
    if args.format == "json":
        text = json.dumps(f, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    elif args.format == "sarif":
        text = json.dumps(to_sarif(f), indent=2, ensure_ascii=False) + "\n"
    else:
        text = _format_text(f)
    _write_or_print(text, args.output)
    if args.output and args.format != "text":
        sys.stdout.write(_format_text(f))
    return f["summary"]["exit_code"]


def cmd_evidence(args) -> int:
    from .evidence import render_markdown

    ev = evidence(args.repo, args.lockfile, args.policy, args.previous_lock)
    os.makedirs(args.output_dir, exist_ok=True)
    with open(os.path.join(args.output_dir, "grantlock-evidence.json"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(ev, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    with open(os.path.join(args.output_dir, "grantlock-evidence.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(render_markdown(ev))
    print(f"wrote grantlock-evidence.json and grantlock-evidence.md ({len(ev['findings'])} findings)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="grantlock", description="Lockfile for the identities an AI agent stack runs as.")
    p.add_argument("--version", action="version", version=f"grantlock {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="print the identity inventory as JSON")
    s.add_argument("--repo", default=".")
    s.add_argument("--output")
    s.set_defaults(func=cmd_scan)
    lk = sub.add_parser("lock", help="(re)generate grantlock.json from the repository")
    lk.add_argument("--repo", default=".")
    lk.add_argument("--lockfile")
    lk.set_defaults(func=cmd_lock)
    c = sub.add_parser("check", help="compare the repository against grantlock.json (CI gate)")
    c.add_argument("--repo", default=".")
    c.add_argument("--lockfile")
    c.add_argument("--policy")
    c.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    c.add_argument("--output")
    c.set_defaults(func=cmd_check)
    ev = sub.add_parser("evidence", help="write an audit evidence pack (JSON + Markdown, no secret values)")
    ev.add_argument("--repo", default=".")
    ev.add_argument("--lockfile")
    ev.add_argument("--policy")
    ev.add_argument("--previous-lock", help="an earlier grantlock.json (e.g. from `git show HEAD~1:grantlock.json`)")
    ev.add_argument("--output-dir", required=True)
    ev.set_defaults(func=cmd_evidence)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except MissingLockfile as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (lockfile.LockfileError, policy_mod.PolicyError, SchemaError, NotADirectoryError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
