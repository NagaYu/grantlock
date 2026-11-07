"""GATE criterion 6: the scanning core performs no network calls (static + runtime)."""

import ast
import socket
from pathlib import Path

import grantlock
from grantlock.check import check
from repo_builder import DEPLOY, base_repo, write

CORE = Path(__file__).parents[1] / "grantlock"
FORBIDDEN = {"socket", "ssl", "http", "urllib.request", "urllib3", "requests", "httpx", "aiohttp", "ftplib",
             "smtplib", "telnetlib", "xmlrpc", "subprocess", "asyncio", "websocket", "websockets", "paramiko"}


def _imports(path):
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module


def test_core_imports_no_network_modules():
    files = sorted(CORE.rglob("*.py"))
    assert len(files) >= 12
    for f in files:
        for mod in _imports(f):
            top = mod.split(".")[0]
            assert mod not in FORBIDDEN and top not in FORBIDDEN, f"{f.name} imports {mod}"


def test_only_urllib_parse_is_used():
    for f in sorted(CORE.rglob("*.py")):
        for mod in _imports(f):
            if mod.startswith("urllib"):
                assert mod == "urllib.parse", f"{f.name}: {mod}"


def test_full_pipeline_with_sockets_disabled(tmp_path, monkeypatch):
    repo = base_repo(tmp_path)
    write(repo, {".github/workflows/deploy.yml": DEPLOY.replace("role/gha-deploy", "role/AdministratorAccess")})

    def boom(*a, **k):
        raise AssertionError("network access attempted")

    for name in ("socket", "create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, boom)
    inv = grantlock.scan(repo)
    grantlock.lock(inv)
    f = check(repo)
    assert f["summary"]["critical"] >= 1
