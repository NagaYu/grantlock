"""Fix round Step 5 (D-044): a real .env file *uses* its variables; templates only declare them."""

import json

from grantlock.parsers.dotenv import parse_env
from repo_builder import base_repo, of_class, run_check, write
from repo_builder import MCP


def test_real_env_files_are_usage_templates_are_declarations():
    for rel, kind in ((".env", "env_use"), (".env.local", "env_use"), ("svc/.env.production", "env_use"),
                      (".env.example", "env_decl"), (".env.sample", "env_decl"), (".env.template", "env_decl"),
                      (".env.production.example", "env_decl")):
        e, _ = parse_env(rel, "API_TOKEN=x\n")
        assert e[0]["component"]["kind"] == kind, rel
        assert e[0]["component"]["name"] == rel


def test_variable_dropped_from_env_is_G8_at_the_env_file(tmp_path):
    repo = base_repo(tmp_path, {".env": "GITHUB_PERSONAL_ACCESS_TOKEN=\nRETIRED_METRICS_TOKEN=\n",
                                ".env.example": "GITHUB_PERSONAL_ACCESS_TOKEN=\nRETIRED_METRICS_TOKEN=\n"})
    write(repo, {".env": "GITHUB_PERSONAL_ACCESS_TOKEN=\n"})
    g8 = of_class(run_check(repo), "G8")
    assert [(g["identity_id"], g["component"]["name"], g["file"]) for g in g8] == [
        ("unknown:RETIRED_METRICS_TOKEN", ".env", ".env")]


def test_env_usage_does_not_count_as_sharing(tmp_path):
    """The MCP server and .env use the same PAT, and .env.production too: not G5 (D-013 style)."""
    repo = base_repo(tmp_path)
    write(repo, {".env": "GITHUB_PERSONAL_ACCESS_TOKEN=\n", ".env.production": "GITHUB_PERSONAL_ACCESS_TOKEN=\n"})
    f = run_check(repo)
    assert of_class(f, "G5") == []


def test_env_usage_keeps_mcp_identity_alive(tmp_path):
    repo = base_repo(tmp_path, {".env": "GITHUB_PERSONAL_ACCESS_TOKEN=\n"})
    write(repo, {".mcp.json": '{"mcpServers": {}}\n'})
    assert of_class(run_check(repo), "G8") == []  # the server stopped, but .env still uses the PAT: not dormant
    write(repo, {".env": None})
    assert {g["component"]["name"] for g in of_class(run_check(repo), "G8")} == {"github", ".env"}
