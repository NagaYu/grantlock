import json
import socket
from pathlib import Path

import pytest

import grantlock
from grantlock import schemas
from secret_guard import assert_no_secret_leak

REPO = Path(__file__).parent / "fixtures" / "repo_basic"


@pytest.fixture(scope="module")
def inv():
    return grantlock.scan(REPO)


def _bindings(inv, identity):
    return sorted(e["component"]["id"] for e in inv["entries"] if e["identity_id"] == identity)


def test_schema_valid(inv):
    schemas.validate(inv, schemas.DOC_INVENTORY)
    assert inv["schema_version"] == "1.0"


def test_surfaces_discovered(inv):
    kinds = {e["component"]["kind"] for e in inv["entries"]}
    assert kinds == {"mcp_server", "gha_workflow", "env_decl"}
    files = {e["component"]["file"] for e in inv["entries"]}
    assert "node_modules/somepkg/.mcp.json" not in files
    assert "package.json" not in files


def test_owner_resolution(inv):
    for e in inv["entries"]:
        f = e["component"]["file"]
        if f.startswith(".github/workflows/"):
            assert e["owner"]["owners"] == ["@acme/platform"]
        elif f in (".mcp.json", ".env.example"):
            assert e["owner"]["owners"] == ["@acme/ai-platform"]
        elif f.startswith("tools/agents/"):
            assert e["owner"] is None  # G4 material


def test_shared_identity_material(inv):
    # G5 material: one identity, several components (env_decl is a declaration)
    assert _bindings(inv, "github:GITHUB_PERSONAL_ACCESS_TOKEN") == [
        "env_decl:.env.example#decl",
        "mcp_server:.mcp.json#github",
        "mcp_server:tools/agents/mcp.json#triage-bot",
    ]
    assert _bindings(inv, "slack:SLACK_BOT_TOKEN") == ["env_decl:.env.example#decl", "mcp_server:.mcp.json#slack"]


def test_entries_sorted_and_deterministic(inv):
    keys = [(e["identity_id"], e["component"]["id"]) for e in inv["entries"]]
    assert keys == sorted(keys)
    again = grantlock.scan(REPO)
    assert json.dumps(inv, sort_keys=True) == json.dumps(again, sort_keys=True)


def test_no_absolute_paths(inv):
    assert str(REPO.resolve()) not in json.dumps(inv)


def test_no_secret_values(inv):
    assert_no_secret_leak(inv)


def test_scan_makes_no_network_calls(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(socket, "socket", boom)
    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    grantlock.scan(REPO)


def test_declared_owner_overrides(tmp_path):
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"s": {"command": "x", "env": {"API_TOKEN": "${API_TOKEN}"}}}}')
    (tmp_path / "grantlock.policy.json").write_text(json.dumps({
        "schema_version": "1.0", "document": "grantlock.policy",
        "declared_owners": {"mcp_server:.mcp.json#s": ["@team/agents"]}}))
    inv = grantlock.scan(tmp_path)
    assert inv["entries"][0]["owner"]["source"] == "declared"
    assert inv["entries"][0]["owner"]["owners"] == ["@team/agents"]


def test_symlinks_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / ".mcp.json").write_text('{"mcpServers": {"s": {"command": "x", "env": {"API_TOKEN": "${API_TOKEN}"}}}}')
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "linked").symlink_to(outside, target_is_directory=True)
    (repo / "linked.mcp.json").symlink_to(outside / ".mcp.json")
    assert grantlock.scan(repo)["entries"] == []


def test_scan_rejects_non_directory(tmp_path):
    with pytest.raises(NotADirectoryError):
        grantlock.scan(tmp_path / "missing")
