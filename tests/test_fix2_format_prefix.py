"""Fix2 B (D-050): every recorded format prefix satisfies the schema; a literal Slack webhook no longer crashes scan()."""

import json

import grantlock
from grantlock import model, schemas
from repo_builder import of_class, relock, run_check, write
from secret_guard import assert_no_secret_leak

HOOK = "https://hooks.slack.com/services/TFAKE0001/BFAKE0002/FAKEwebhookSecret0000000"
CLEAN = {"mcpServers": {"notify": {"command": "npx", "args": ["-y", "@acme/notify-mcp"],
                                   "env": {"SLACK_WEBHOOK_URL": "${SLACK_WEBHOOK_URL}"}}}}


def test_every_format_prefix_fits_the_schema():
    fmt_schema = schemas.INVENTORY_SCHEMA["$defs"]["format"]
    limit = fmt_schema["properties"]["prefix"]["maxLength"]
    from jsonschema import Draft202012Validator
    v = Draft202012Validator(fmt_schema)
    for cls, prefix, _rx in model.FORMAT_TABLE:
        assert prefix is None or len(prefix) <= limit, (cls, prefix)
        assert not list(v.iter_errors({"class": cls, "prefix": prefix})), cls
        assert cls in schemas.FORMAT_CLASSES


def test_classified_prefix_is_a_table_constant_not_the_value():
    fmt = model.classify_literal(HOOK)
    assert fmt["class"] == "slack_webhook_url"
    assert fmt["prefix"] in {p for _c, p, _r in model.FORMAT_TABLE}
    assert "services" not in (fmt["prefix"] or "") and "FAKE" not in (fmt["prefix"] or "")


def test_literal_webhook_in_mcp_scans_and_is_G1(tmp_path):
    repo = tmp_path / "r"
    repo.mkdir()
    write(repo, {".github/CODEOWNERS": "* @acme/ai\n", ".mcp.json": json.dumps(CLEAN, indent=2)})
    relock(repo)
    leak = json.loads(json.dumps(CLEAN))
    leak["mcpServers"]["notify"]["env"]["SLACK_WEBHOOK_URL"] = HOOK
    write(repo, {".mcp.json": json.dumps(leak, indent=2)})
    inv = grantlock.scan(repo)  # must not raise
    schemas.validate(inv, schemas.DOC_INVENTORY)
    g1 = of_class(run_check(repo), "G1")
    assert [(g["component"]["name"], g["details"]["format"]["class"]) for g in g1] == [("notify", "slack_webhook_url")]
    assert_no_secret_leak(inv, [HOOK, "FAKEwebhookSecret0000000"])
