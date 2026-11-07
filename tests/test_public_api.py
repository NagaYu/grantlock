"""D-032: the documented library API stays callable after submodule imports."""

import importlib

import grantlock


def test_public_functions_callable_after_submodule_imports(tmp_path):
    importlib.import_module("grantlock.diff")
    from grantlock.diff import diff as _d  # noqa: F401
    import grantlock.inventory  # noqa: F401
    import grantlock.lockfile  # noqa: F401
    assert callable(grantlock.scan) and callable(grantlock.lock) and callable(grantlock.diff)
    (tmp_path / ".mcp.json").write_text('{"mcpServers": {"s": {"command": "x", "env": {"API_TOKEN": "${API_TOKEN}"}}}}')
    inv = grantlock.scan(tmp_path)
    f = grantlock.diff(inv, grantlock.lock(inv))
    assert f["document"] == "grantlock.findings" and f["findings"] == [] or all(x["class"] == "G4" for x in f["findings"])
