"""check: scan + read lockfile + diff. Reads only; never writes grantlock.json."""

from __future__ import annotations

import os
from typing import Any

from . import lockfile, policy as policy_mod
from .diff import diff
from .inventory import scan


class MissingLockfile(FileNotFoundError):
    pass


def check(repo_path: str | os.PathLike[str], lock_path: str | os.PathLike[str] | None = None,
          policy_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    repo = os.fspath(repo_path)
    lp = os.fspath(lock_path) if lock_path is not None else os.path.join(repo, lockfile.LOCK_FILENAME)
    if not os.path.isfile(lp):
        raise MissingLockfile(f"no lockfile at {os.path.basename(lp)}; run `grantlock lock` and commit it")
    pp = os.fspath(policy_path) if policy_path is not None else os.path.join(repo, policy_mod.POLICY_FILENAME)
    pol = policy_mod.load_policy(pp)
    return diff(scan(repo), lockfile.read(lp), pol)


def evidence(repo_path: str | os.PathLike[str], lock_path: str | os.PathLike[str] | None = None,
             policy_path: str | os.PathLike[str] | None = None,
             previous_lock_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Build the evidence pack. Reads only; never writes grantlock.json."""
    from .evidence import build_evidence

    repo = os.fspath(repo_path)
    lp = os.fspath(lock_path) if lock_path is not None else os.path.join(repo, lockfile.LOCK_FILENAME)
    if not os.path.isfile(lp):
        raise MissingLockfile(f"no lockfile at {os.path.basename(lp)}; run `grantlock lock` and commit it")
    pp = os.fspath(policy_path) if policy_path is not None else os.path.join(repo, policy_mod.POLICY_FILENAME)
    pol = policy_mod.load_policy(pp)
    inv = scan(repo)
    lock = lockfile.read(lp)
    previous = lockfile.read(previous_lock_path) if previous_lock_path is not None else None
    return build_evidence(inv, lock, diff(inv, lock, pol), pol, previous)
