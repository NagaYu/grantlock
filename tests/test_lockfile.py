import json
import re
import shutil
from pathlib import Path

import pytest

import grantlock
from grantlock import lockfile, schemas
from secret_guard import assert_no_secret_leak

REPO = Path(__file__).parent / "fixtures" / "repo_basic"


@pytest.fixture(scope="module")
def lk():
    return grantlock.lock(grantlock.scan(REPO))


def test_lock_schema_and_version(lk):
    schemas.validate(lk, schemas.DOC_LOCK)
    assert lk["schema_version"] == "1.0" and lk["document"] == "grantlock.lock"


def test_lock_is_byte_deterministic(lk):
    a = lockfile.dumps(lk)
    b = lockfile.dumps(grantlock.lock(grantlock.scan(REPO)))
    assert a == b
    assert a.endswith("\n")


def test_lock_has_no_timestamps_or_abs_paths(lk):
    text = lockfile.dumps(lk)
    assert not re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}", text)
    assert str(REPO.resolve()) not in text


def test_lock_drops_evidence_and_sorts(lk):
    assert all("evidence" not in e for e in lk["entries"])
    keys = [(e["identity_id"], e["component"]["id"]) for e in lk["entries"]]
    assert keys == sorted(keys)


def test_lock_stable_under_line_moves(tmp_path, lk):
    repo = tmp_path / "r"
    shutil.copytree(REPO, repo)
    p = repo / ".mcp.json"
    p.write_text("\n\n\n" + p.read_text())
    assert lockfile.dumps(grantlock.lock(grantlock.scan(repo))) == lockfile.dumps(lk)


def test_roundtrip(tmp_path, lk):
    path = tmp_path / "grantlock.json"
    lockfile.write(path, lk)
    assert lockfile.read(path) == lk
    assert not (tmp_path / "grantlock.json.tmp").exists()


def test_no_secret_values(lk):
    assert_no_secret_leak(lockfile.dumps(lk))


@pytest.mark.parametrize("text,msg", [
    ("not json", "not valid JSON"),
    ("[]", "JSON object"),
    ('{"schema_version": "2.0", "document": "grantlock.lock", "entries": []}', "schema_version"),
    ('{"schema_version": "1.0", "document": "grantlock.lock", "entries": []}', "schema violation"),
])
def test_invalid_lockfiles_rejected(text, msg):
    with pytest.raises(lockfile.LockfileError, match=msg):
        lockfile.loads(text)


def test_tampered_entry_rejected(lk):
    bad = json.loads(lockfile.dumps(lk))
    bad["entries"][0]["credential"]["value"] = "x"
    with pytest.raises(lockfile.LockfileError):
        lockfile.loads(json.dumps(bad))
