import pytest

from grantlock import model


@pytest.mark.parametrize("name,ctx,expected", [
    ("OPENAI_API_KEY", [], "openai"),
    ("ANTHROPIC_API_KEY", [], "anthropic"),
    ("GITHUB_PERSONAL_ACCESS_TOKEN", [], "github"),
    ("GH_TOKEN", [], "github"),
    ("AWS_SECRET_ACCESS_KEY", [], "aws"),
    ("GOOGLE_APPLICATION_CREDENTIALS", [], "gcp"),
    ("AZURE_CLIENT_SECRET", [], "azure"),
    ("SLACK_BOT_TOKEN", [], "slack"),
    ("DATABASE_URL", [], "postgres"),
    ("API_KEY", ["@modelcontextprotocol/server-brave-search"], "brave"),
    ("TOKEN", ["https://api.githubcopilot.com/mcp/"], "github"),
    ("API_KEY", [], "unknown"),
])
def test_infer_provider(name, ctx, expected):
    assert model.infer_provider(name, ctx) == expected


@pytest.mark.parametrize("name", [
    "OPENAI_API_KEY", "GITHUB_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "DATABASE_URL", "SLACK_WEBHOOK_URL",
    "AZURE_CLIENT_SECRET", "GOOGLE_APPLICATION_CREDENTIALS", "SENTRY_DSN", "OPENAI_KEY",
    "Authorization", "X-API-Key", "api-key", "GCP_SA_KEY", "GH_APP_PRIVATE_KEY",
])
def test_credential_names(name):
    assert model.is_credential_name(name)


@pytest.mark.parametrize("name", [
    "LOG_LEVEL", "PORT", "NODE_ENV", "STRIPE_PUBLISHABLE_KEY", "PUBLIC_KEY", "GITHUB_TOOLSETS",
    "SLACK_TEAM_ID", "AWS_REGION", "CACHE_KEY", "GOOGLE_OAUTH_SCOPES", "SNOWFLAKE_ROLE",
    "AZURE_CLIENT_ID", "PGHOST", "SORT_KEY",
])
def test_non_credential_names(name):
    assert not model.is_credential_name(name)


@pytest.mark.parametrize("name,ctype", [
    ("OPENAI_API_KEY", "api_key"),
    ("AWS_ACCESS_KEY_ID", "api_key"),
    ("GITHUB_TOKEN", "token"),
    ("NPM_TOKEN", "token"),
    ("AZURE_CLIENT_SECRET", "oauth"),
    ("GOOGLE_OAUTH_REFRESH_TOKEN", "oauth"),
    ("GCP_SA_KEY", "service_account"),
    ("GOOGLE_APPLICATION_CREDENTIALS", "service_account"),
    ("AZURE_CREDENTIALS", "service_account"),
    ("DB_PASSWORD", "password"),
    ("DATABASE_URL", "password"),
    ("SLACK_WEBHOOK_URL", "token"),
    ("WEIRD_SECRET", "unknown"),
])
def test_classify_type(name, ctype):
    assert model.classify_type(name) == ctype


def test_identity_id_deterministic_and_aliased():
    assert model.identity_id("openai", "OPENAI_API_KEY") == "openai:OPENAI_API_KEY"
    assert model.identity_id("aws", "AWS_SECRET_ACCESS_KEY") == model.identity_id("aws", "AWS_ACCESS_KEY_ID")


@pytest.mark.parametrize("value", ["", "${OPENAI_API_KEY}", "${env:X}", "$TOKEN", "${input:gh_token}",
                                   "${{ secrets.X }}", "<your-api-key>", "your_api_key_here",
                                   "sk-your-key-here", "changeme", "xxxx", "TODO", "..."])
def test_references_and_placeholders_are_not_secrets(value):
    assert not model.literal_is_secret("OPENAI_API_KEY", value)


@pytest.mark.parametrize("value,cls,prefix", [
    ("sk-FAKEaaaaaaaaaaaaaaaaaaaa", "openai_key", "sk-"),
    ("sk-ant-FAKE0000000000000000", "anthropic_key", "sk-ant-"),
    ("ghp_FAKE00000000000000000000000000000000", "github_pat_classic", "ghp_"),
    ("github_pat_FAKE_0000000000", "github_pat_fine_grained", "github_pat_"),
    ("AKIAFAKEFAKE00000000", "aws_access_key_id", "AKIA"),
    ("xoxb-FAKE-000000000000", "slack_token", "xox"),
    ("Bearer ghp_FAKE00000000000000000000000000000000", "github_pat_classic", "ghp_"),
    ("Bearer FAKEopaque0000", "bearer_literal", None),
    ("postgres://app:FAKEpw@db.prod.internal:5432/app", "connection_string_with_password", None),
])
def test_known_shapes(value, cls, prefix):
    assert model.literal_is_secret(None, value)
    fmt = model.classify_literal(value)
    assert fmt == {"class": cls, "prefix": prefix}
    # the recorded format never contains the value beyond the table prefix
    assert value not in str(fmt) or value == prefix


def test_generic_literal_requires_credential_name():
    assert model.literal_is_secret("DB_PASSWORD", "FAKE-hunter2")
    assert model.classify_literal("FAKE-hunter2") == {"class": "generic_literal", "prefix": None}
    assert not model.literal_is_secret("LOG_LEVEL", "debug")


@pytest.mark.parametrize("value", ["true", "8080", "/etc/creds/key.json", "https://api.example.com/v1",
                                   "postgres://app:${DB_PASSWORD}@db/app", "postgres://app@db/app"])
def test_config_literals_not_secret(value):
    assert not model.literal_is_secret("SOME_TOKEN", value)


def test_url_host_strips_userinfo():
    assert model.url_host("postgres://app:FAKEpw@db.prod.internal:5432/app") == "db.prod.internal"
    assert model.url_host("https://mcp.linear.app/sse") == "mcp.linear.app"
    assert model.url_host("not a url") is None


@pytest.mark.parametrize("scopes,source,hit", [
    ([], "write-all", True),
    (["repo", "admin:org"], "declared", True),
    (["toolset:*"], "declared", True),
    (["role:AdministratorAccess"], "declared", True),
    (["role:ACCOUNTADMIN"], "declared", True),
    (["role:roles/owner"], "declared", True),
    (["contents:write", "id-token:write"], "explicit", False),
    (["role:gha-deploy-readonly"], "declared", False),
    (["channels:read", "chat:write"], "declared", False),
])
def test_wildcard(scopes, source, hit):
    assert bool(model.wildcard_reasons(scopes, source)) is hit


def test_lifespan_rules():
    assert model.lifespan_for("federated", "service_account") == "ephemeral"
    assert model.lifespan_for("vault_ref", "api_key") == "long_lived"
    assert model.lifespan_for("env", "unknown") == "unknown"
    assert model.lifespan_for("vault_ref", "oauth") == "rotating"
