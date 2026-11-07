import re
from pathlib import Path

import pytest

from grantlock.parsers.dotenv import declared_names, is_env_file, parse_env
from secret_guard import assert_no_secret_leak

FX = Path(__file__).parent / "fixtures" / "dotenv"


def test_is_env_file():
    assert is_env_file(".env") and is_env_file(".env.example") and is_env_file("svc/.env.production")
    assert not is_env_file(".envrc") and not is_env_file("env.py") and not is_env_file(".env.")


def test_example_declares_names_only():
    entries, warnings = parse_env(".env.example", (FX / "env.example").read_text())
    assert warnings == []
    assert [e["identity_id"] for e in entries] == [
        "anthropic:ANTHROPIC_API_KEY",
        "github:GITHUB_PERSONAL_ACCESS_TOKEN",
        "openai:OPENAI_API_KEY",
        "postgres:DATABASE_URL",
    ]
    for e in entries:
        assert e["component"]["kind"] == "env_decl"
        assert e["component"]["file"] == ".env.example"
        assert e["credential"]["storage"] == "env"
        assert e["credential"]["format"] is None
        assert e["scopes"] == [] and e["scopes_known"] is False
        assert e["resources"] == []
    db = [e for e in entries if e["credential"]["name"] == "DATABASE_URL"][0]
    assert db["credential"]["type"] == "password"
    assert db["evidence"] == [{"file": ".env.example", "line": 5, "locator": "DATABASE_URL"}]


def test_values_never_in_output():
    entries, _ = parse_env(".env", (FX / "env.leaky").read_text())
    assert_no_secret_leak(entries)
    names = sorted(e["credential"]["name"] for e in entries)
    assert names == ["AWS_ACCESS_KEY_ID", "DB_PASSWORD", "GH_APP_PRIVATE_KEY", "OPENAI_API_KEY", "SLACK_BOT_TOKEN"]
    # stored as env reference: .env values are not read, so never classified as inline
    assert all(e["credential"]["storage"] == "env" for e in entries)


def test_multiline_quoted_value_lines_are_not_declarations():
    names = [n for n, _ in declared_names((FX / "env.leaky").read_text())]
    assert "FAKE_NOT_A_NAME_TOKEN" not in names
    assert "MIIFAKEBASE64LINE" not in names
    assert names[-2:] == ["SLACK_BOT_TOKEN", "PORT"]


def test_output_independent_of_values():
    """Property: replacing every value with something else changes nothing."""
    text = (FX / "env.leaky").read_text()
    a, _ = parse_env(".env", text)
    swapped = re.sub(r"=(?!\s*\").*$", "=OTHER_VALUE", text, flags=re.M)
    b, _ = parse_env(".env", swapped)
    assert a == b


def test_environment_from_file_suffix():
    e, _ = parse_env("deploy/.env.production", "API_TOKEN=x\n")
    assert e[0]["resources"] == [{"kind": "environment", "value": "production"}]
    e, _ = parse_env(".env.production.example", "API_TOKEN=x\n")
    assert e[0]["resources"] == []


def test_parser_source_never_binds_value_group():
    src = (Path(__file__).parents[1] / "grantlock" / "parsers" / "dotenv.py").read_text()
    # the declaration regex captures exactly one group: the name
    assert re.search(r'_DECL = re\.compile\(r"\^\\s\*\(\?:export\\s\+\)\?\(\[A-Za-z_\]\[A-Za-z0-9_\.\]\*\)\\s\*="\)', src)
