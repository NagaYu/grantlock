import copy

import pytest

from grantlock import schemas
from grantlock.model import GENERATOR, make_component, make_entry


def _entry(**over):
    comp = make_component("mcp_server", "github", ".mcp.json")
    e = make_entry(
        identity="github:GITHUB_PERSONAL_ACCESS_TOKEN",
        component=comp,
        provider="github",
        ctype="token",
        name="GITHUB_PERSONAL_ACCESS_TOKEN",
        storage="env",
        evidence=[{"file": ".mcp.json", "line": 7, "locator": "mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN"}],
    )
    e.update(over)
    return e


def _inventory(entries):
    return {
        "schema_version": schemas.SCHEMA_VERSION,
        "document": schemas.DOC_INVENTORY,
        "generator": dict(GENERATOR),
        "entries": entries,
        "warnings": [],
    }


def test_inventory_valid():
    schemas.validate(_inventory([_entry()]), schemas.DOC_INVENTORY)


def test_inventory_requires_schema_version():
    doc = _inventory([_entry()])
    del doc["schema_version"]
    with pytest.raises(schemas.SchemaError):
        schemas.validate(doc, schemas.DOC_INVENTORY)


def test_inventory_rejects_wrong_version():
    doc = _inventory([_entry()])
    doc["schema_version"] = "0.9"
    assert schemas.validation_errors(doc, schemas.DOC_INVENTORY)


def test_entry_is_closed_no_value_field_allowed():
    e = _entry()
    e["credential"]["value"] = "anything"
    assert schemas.validation_errors(_inventory([e]), schemas.DOC_INVENTORY)
    e = _entry()
    e["value"] = "anything"
    assert schemas.validation_errors(_inventory([e]), schemas.DOC_INVENTORY)


def test_format_class_is_closed_enum():
    e = _entry()
    e["credential"]["storage"] = "inline"
    e["credential"]["format"] = {"class": "free-text-not-allowed", "prefix": None}
    assert schemas.validation_errors(_inventory([e]), schemas.DOC_INVENTORY)
    e["credential"]["format"] = {"class": "openai_key", "prefix": "sk-"}
    assert not schemas.validation_errors(_inventory([e]), schemas.DOC_INVENTORY)


@pytest.mark.parametrize("field,bad", [
    ("lifespan", "forever"),
    ("scope_source", "magic"),
])
def test_enums_enforced(field, bad):
    e = _entry(**{field: bad})
    assert schemas.validation_errors(_inventory([e]), schemas.DOC_INVENTORY)


def test_component_kind_enum():
    e = _entry()
    e["component"]["kind"] = "k8s"
    assert schemas.validation_errors(_inventory([e]), schemas.DOC_INVENTORY)


def test_lock_schema():
    lock = {
        "schema_version": "1.0",
        "document": schemas.DOC_LOCK,
        "generator": dict(GENERATOR),
        "entries": [_entry()],
    }
    schemas.validate(lock, schemas.DOC_LOCK)
    bad = copy.deepcopy(lock)
    bad["document"] = schemas.DOC_INVENTORY
    assert schemas.validation_errors(bad, schemas.DOC_LOCK)


def test_findings_schema():
    comp = make_component("mcp_server", "github", ".mcp.json")
    doc = {
        "schema_version": "1.0",
        "document": schemas.DOC_FINDINGS,
        "generator": dict(GENERATOR),
        "summary": {"critical": 0, "warning": 1, "note": 0, "total": 1, "by_class": {"G4": 1},
                    "exit_code": 0, "lock_in_sync": True},
        "findings": [{
            "finding_id": "G4:x", "class": "G4", "title": "t", "severity": "warning",
            "change": "unchanged", "identity_id": "x", "component": comp, "file": ".mcp.json",
            "line": None, "production": {"value": False, "evidence": []}, "details": {},
            "message": "m",
        }],
        "drift": [],
    }
    schemas.validate(doc, schemas.DOC_FINDINGS)
    doc["findings"][0]["details"]["secret"] = "x"
    assert schemas.validation_errors(doc, schemas.DOC_FINDINGS)


def test_policy_schema():
    pol = {"schema_version": "1.0", "document": schemas.DOC_POLICY,
           "severity": {"G4": {"production": "critical", "non_production": "warning"}}}
    schemas.validate(pol, schemas.DOC_POLICY)
    pol["severity"]["G4"]["production"] = "fatal"
    assert schemas.validation_errors(pol, schemas.DOC_POLICY)


def test_schema_for_returns_copy():
    s = schemas.schema_for(schemas.DOC_INVENTORY)
    s["properties"] = {}
    assert schemas.INVENTORY_SCHEMA["properties"]
