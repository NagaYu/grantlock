from pathlib import Path

from grantlock.parsers.compose import is_compose_file, parse_compose
from secret_guard import assert_no_secret_leak

FX = Path(__file__).parent / "fixtures" / "compose"
SECRETS = [
    "sk-proj-FAKEdefault0000000000000000000000T3BlbkFJ000000000000000000000000",
    "sk_live_FAKEcomposeLeak00000000000000",
    "npm_FAKEbuildArgLeak00000000000000000000",
    "FAKEcomposePw99",
]


def _parse(rel="compose.yaml"):
    return parse_compose(rel, (FX / "compose.yaml").read_text())


def _by(entries):
    return {(e["identity_id"], e["component"]["name"]): e for e in entries}


def test_discovery_names():
    for n in ("compose.yaml", "compose.yml", "docker-compose.yml", "docker-compose.prod.yaml", "infra/compose.override.yml"):
        assert is_compose_file(n), n
    for n in ("composer.json", "my-compose.yml", "compose.json"):
        assert not is_compose_file(n), n


def test_environment_map_and_list_forms():
    entries, warnings = _parse()
    assert warnings == []
    b = _by(entries)
    assert b[("anthropic:ANTHROPIC_API_KEY", "agent")]["credential"]["storage"] == "env"
    # credential-named key with a partial reference keeps the key name (same rule as MCP, D-008)
    assert b[("postgres:DATABASE_URL", "agent")]["credential"]["storage"] == "env"
    assert b[("github:GITHUB_TOKEN", "agent")]["credential"]["storage"] == "env"  # passthrough (map, null)
    assert b[("sentry:SENTRY_DSN", "worker")]["credential"]["storage"] == "env"  # passthrough (list, bare)
    assert b[("stripe:STRIPE_SECRET_KEY", "worker")]["credential"]["storage"] == "inline"
    assert b[("stripe:STRIPE_SECRET_KEY", "worker")]["component"] == {
        "id": "compose_service:compose.yaml#worker", "kind": "compose_service", "name": "worker", "file": "compose.yaml"}
    # non-credential configuration is ignored
    assert not any("LOG_LEVEL" in i or "PORT" in i or "QUEUE_URL" in i or "CACHE_DIR" in i for i, _ in b)


def test_secret_in_interpolation_default_is_inline():
    b = _by(_parse()[0])
    e = b[("openai:OPENAI_API_KEY", "agent")]
    assert e["credential"]["storage"] == "inline"
    assert e["credential"]["format"] == {"class": "openai_key", "prefix": "sk-"}


def test_build_args_and_connection_strings():
    b = _by(_parse()[0])
    assert b[("npm:NPM_TOKEN", "worker")]["credential"]["format"]["class"] == "npm_token"
    url = [e for (i, c), e in b.items() if c == "db" and i.endswith("POSTGRES_URL_ADMIN")][0]
    assert url["credential"]["storage"] == "inline"
    assert url["credential"]["format"]["class"] == "connection_string_with_password"
    assert {"kind": "host", "value": "db.prod.internal"} in url["resources"]


def test_env_file_shared_identity():
    entries, _ = _parse()
    users = sorted(e["component"]["name"] for e in entries if e["identity_id"] == "local:env_file:config/shared.env")
    assert users == ["agent", "worker"]  # G5 material: one env_file, two services


def test_secrets_references_and_definitions():
    b = _by(_parse()[0])
    slack = b[("slack:slack_bot_token", "agent")]
    assert slack["credential"]["storage"] == "env"  # top-level secret sourced from environment
    pg = b[("postgres:pg_password", "db")]
    assert pg["credential"]["storage"] == "vault_ref"  # file-backed: contents never read
    assert pg["credential"]["type"] == "password"
    # top-level secret no service uses produces no binding (becomes G8 only when a lock had a user)
    assert not any("unused_legacy_token" in i for i, _ in b)


def test_static_cloud_key_has_short_lived_alternative():
    b = _by(_parse()[0])
    aws = b[("aws:AWS_ACCESS_KEY_ID", "mcp-gateway")]
    assert aws["context"]["federation_available"] is True and len(aws["evidence"]) == 2


def test_environment_from_override_file_name():
    text = "services:\n  api:\n    environment:\n      API_TOKEN: ${API_TOKEN}\n"
    e, _ = parse_compose("deploy/docker-compose.prod.yml", text)
    assert {"kind": "environment", "value": "prod"} in e[0]["resources"]
    e, _ = parse_compose("docker-compose.override.yml", text)
    assert not any(r["kind"] == "environment" for r in e[0]["resources"])


def test_values_never_in_output():
    entries, warnings = _parse()
    assert_no_secret_leak(entries, SECRETS)
    assert_no_secret_leak(warnings, SECRETS)


def test_secret_file_contents_never_read(tmp_path):
    # the parser is pure over the compose text: it has no way to open secrets/*.txt
    import inspect
    from grantlock.parsers import compose
    src = inspect.getsource(compose)
    assert "open(" not in src and "read_text" not in src


def test_not_compose_or_broken():
    assert parse_compose("compose.yaml", "version: '3'\n") == ([], [])
    entries, warnings = parse_compose("compose.yaml", "services: [unclosed")
    assert entries == [] and warnings


def test_undefined_secret_warns():
    _, w = parse_compose("compose.yaml", "services:\n  a:\n    secrets: [missing_one]\n")
    assert any("undefined secret" in x["message"] for x in w)


def test_deterministic():
    assert _parse() == _parse()


def test_credential_file_path_is_a_reference():
    text = "services:\n  w:\n    environment:\n      GOOGLE_APPLICATION_CREDENTIALS: /run/secrets/gcp.json\n      CACHE_DIR: /tmp/x\n"
    entries, _ = parse_compose("compose.yaml", text)
    assert [(e["identity_id"], e["credential"]["storage"]) for e in entries] == [("gcp:GOOGLE_APPLICATION_CREDENTIALS", "env")]
    assert entries[0]["context"]["federation_available"] is True
