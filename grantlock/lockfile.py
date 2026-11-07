"""grantlock.json: generation, canonical serialization, reading and validation."""

from __future__ import annotations

import copy
import json
import os
from typing import Any

from . import model, schemas

LOCK_FILENAME = "grantlock.json"


class LockfileError(ValueError):
    pass


def lock(inventory: dict[str, Any]) -> dict[str, Any]:
    """inventory -> lockfile. Pure. Evidence (line numbers) is dropped so that
    moving lines does not churn the lockfile; everything else is kept."""
    schemas.validate(inventory, schemas.DOC_INVENTORY)
    entries = []
    for e in inventory["entries"]:
        x = copy.deepcopy(e)
        x.pop("evidence", None)
        entries.append(x)
    entries.sort(key=lambda x: (x["identity_id"], x["component"]["id"]))
    doc = {
        "schema_version": schemas.SCHEMA_VERSION,
        "document": schemas.DOC_LOCK,
        "generator": dict(model.GENERATOR),
        "entries": entries,
    }
    schemas.validate(doc, schemas.DOC_LOCK)
    return doc


def dumps(doc: dict[str, Any]) -> str:
    """Canonical serialization: sorted keys, 2-space indent, trailing newline."""
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def loads(text: str) -> dict[str, Any]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise LockfileError(f"grantlock.json is not valid JSON (line {exc.lineno})") from None
    if not isinstance(doc, dict):
        raise LockfileError("grantlock.json must be a JSON object")
    ver = doc.get("schema_version")
    if not isinstance(ver, str) or ver.split(".")[0] != schemas.SCHEMA_VERSION.split(".")[0]:
        raise LockfileError(f"unsupported grantlock.json schema_version: {ver!r}")
    errs = schemas.validation_errors(doc, schemas.DOC_LOCK)
    if errs:
        raise LockfileError("grantlock.json schema violation: " + "; ".join(errs[:5]))
    return doc


def read(path: str | os.PathLike[str]) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return loads(fh.read())


def write(path: str | os.PathLike[str], doc: dict[str, Any]) -> None:
    schemas.validate(doc, schemas.DOC_LOCK)
    tmp = f"{os.fspath(path)}.tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(dumps(doc))
    os.replace(tmp, path)
