from pathlib import Path

import pytest

from grantlock.parsers.mcp import is_mcp_config, parse_mcp
from secret_guard import assert_no_secret_leak

FX = Path(__file__).parent / "fixtures" / "mcp"


def _parse(name, rel=".mcp.json"):
    return parse_mcp(rel, (FX / name).read_text())


def _by_id(entries):
    return {e["identity_id"]: e for e in entries}


def test_clean_config_all_references():
    entries, warnings = _parse("clean.mcp.json")
    assert warnings == []
    ids = _by_id(entries)
    assert set(ids) == {
        "github:GITHUB_PERSONAL_ACCESS_TOKEN",
        "postgres:PG_READONLY_PASSWORD",
        "slack:SLACK_BOT_TOKEN",
        "brave:BRAVE_API_KEY",
    }
    assert all(e["credential"]["storage"] == "env" for e in entries)
    assert all(e["credential"]["format"] is None for e in entries)
    gh = ids["github:GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert gh["component"] == {"id": "mcp_server:.mcp.json#github", "kind": "mcp_server",
                               "name": "github", "file": ".mcp.json"}
    assert gh["scopes"] == ["toolset:issues", "toolset:pull_requests", "toolset:repos"]
    assert gh["scopes_known"] is True and gh["scope_source"] == "declared"
    assert {"kind": "image", "value": "ghcr.io/github/github-mcp-server"} in gh["resources"]
    assert gh["credential"]["type"] == "token"
    assert gh["lifespan"] == "long_lived"
    pg = ids["postgres:PG_READONLY_PASSWORD"]
    assert {"kind": "host", "value": "db.staging.internal"} in pg["resources"]
    assert pg["credential"]["type"] == "password"
    # non-credential env vars (LOG_LEVEL, SLACK_TEAM_ID) produce nothing
    assert not any("LOG_LEVEL" in i or "TEAM_ID" in i for i in ids)
    # stdio server without credentials: no identity
    assert not any(e["component"]["name"] == "filesystem" for e in entries)


def test_evidence_has_lines_and_locators_only():
    entries, _ = _parse("clean.mcp.json")
    gh = _by_id(entries)["github:GITHUB_PERSONAL_ACCESS_TOKEN"]
    assert gh["evidence"] == [{"file": ".mcp.json", "line": 8,
                               "locator": "mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN"}]


def test_inline_detection_records_only_format():
    entries, _ = _parse("leaky.mcp.json")
    inline = {e["identity_id"]: e["credential"]["format"] for e in entries if e["credential"]["storage"] == "inline"}
    assert inline == {
        "openai:OPENAI_API_KEY": {"class": "openai_key", "prefix": "sk-"},
        "github:mcp_server:.mcp.json#github-remote:headers.Authorization": {"class": "github_pat_classic", "prefix": "ghp_"},
        "postgres:mcp_server:.mcp.json#prod-db:args[2]": {"class": "connection_string_with_password", "prefix": None},
        "anthropic:mcp_server:.mcp.json#claude-proxy:args.api-key": {"class": "anthropic_key", "prefix": "sk-ant-"},
        "unknown:mcp_server:.mcp.json#search:url.api_key": {"class": "generic_literal", "prefix": None},
        "hubspot:mcp_server:.mcp.json#crm:oauth.clientSecret": {"class": "generic_literal", "prefix": None},
    }
    prod = [e for e in entries if e["component"]["name"] == "prod-db"][0]
    assert {"kind": "host", "value": "db.prod.internal"} in prod["resources"]


def test_inline_values_never_in_output():
    entries, warnings = _parse("leaky.mcp.json")
    assert entries
    assert_no_secret_leak(entries)
    assert_no_secret_leak(warnings)


def test_vscode_jsonc_servers_inputs_and_oauth():
    entries, warnings = _parse("vscode.mcp.json", rel=".vscode/mcp.json")
    assert warnings == []
    ids = _by_id(entries)
    gh = ids["github:github_token"]
    assert gh["credential"]["storage"] == "env"  # ${input:...} is a prompted reference, not inline
    assert gh["credential"]["type"] == "token"
    lin = ids["linear:oauth:mcp.linear.app"]
    assert lin["credential"]["type"] == "oauth"
    assert lin["credential"]["storage"] == "vault_ref"
    assert lin["lifespan"] == "rotating"
    snow = ids["snowflake:SNOWFLAKE_PASSWORD"]
    assert set(snow["scopes"]) == {"role:ACCOUNTADMIN", "toolset:*"}
    slack = ids["slack:SLACK_BOT_TOKEN"]
    assert slack["scopes"] == ["channels:read", "chat:write"]


def test_invalid_json_warns():
    entries, warnings = parse_mcp(".mcp.json", '{"mcpServers": {')
    assert entries == []
    assert warnings and warnings[0]["file"] == ".mcp.json"


def test_non_mcp_json_ignored():
    assert parse_mcp("package.json", '{"name": "x", "servers": {}}') == ([], [])
    assert not is_mcp_config("config/servers.json", {"servers": {"a": {}}})
    assert is_mcp_config("config/mcp-servers.json", {"servers": {"a": {}}})


def test_static_aws_key_in_mcp_has_federation_context():
    text = '{"mcpServers": {"aws": {"command": "uvx", "args": ["awslabs.core-mcp-server"], ' \
           '"env": {"AWS_ACCESS_KEY_ID": "${AWS_ACCESS_KEY_ID}", "AWS_SECRET_ACCESS_KEY": "${AWS_SECRET_ACCESS_KEY}"}}}}'
    entries, _ = parse_mcp(".mcp.json", text)
    assert len(entries) == 1  # key pair merged into one identity
    e = entries[0]
    assert e["identity_id"] == "aws:AWS_ACCESS_KEY_ID"
    assert e["context"]["federation_available"] is True
    assert e["lifespan"] == "long_lived"
    assert len(e["evidence"]) == 2


def test_deterministic_output():
    a = _parse("leaky.mcp.json")
    b = _parse("leaky.mcp.json")
    assert a == b


@pytest.mark.parametrize("value", ["", "${OPENAI_API_KEY}", "<your-openai-key>", "sk-your-key-here"])
def test_placeholders_are_env(value):
    text = '{"mcpServers": {"o": {"command": "x", "env": {"OPENAI_API_KEY": "%s"}}}}' % value
    entries, _ = parse_mcp(".mcp.json", text)
    assert [e["credential"]["storage"] for e in entries] == ["env"]
