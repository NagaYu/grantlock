"""Versioned JSON schemas for every document GrantLock emits or consumes.

Schemas are code-resident data (no network resolution). Validation uses
jsonschema Draft 2020-12. Objects are closed (``additionalProperties: false``)
so that free-form strings -- the most likely vehicle for an accidental secret
leak -- have as few places to hide as possible.
"""

from __future__ import annotations

import copy
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_VERSION = "1.0"

DOC_INVENTORY = "grantlock.inventory"
DOC_LOCK = "grantlock.lock"
DOC_FINDINGS = "grantlock.findings"
DOC_POLICY = "grantlock.policy"
DOC_EVIDENCE = "grantlock.evidence"

COMPONENT_KINDS = [
    "mcp_server", "gha_workflow", "env_decl",
    # a real (non-template) .env file *uses* its variables (D-044)
    "env_use",
    # Phase 2 surfaces (D-022): consumers
    "compose_service", "k8s_workload", "terraform_workload",
    # Phase 2 surfaces: declarations (not counted as consumers for G5/G8)
    "k8s_service_account", "k8s_secret", "k8s_rbac", "terraform",
]
# Declaration components hold or define a grant but do not *use* it.
DECLARATION_KINDS = {"env_decl", "k8s_service_account", "k8s_secret", "k8s_rbac", "terraform"}
# Kinds that are not counted as "sharing" an identity for G5: declarations, and local .env usage (D-044).
SHARING_EXCLUDED_KINDS = DECLARATION_KINDS | {"env_use"}
CREDENTIAL_TYPES = ["api_key", "oauth", "service_account", "token", "password", "unknown"]
STORAGE_CLASSES = ["vault_ref", "env", "inline", "federated"]
LIFESPANS = ["ephemeral", "rotating", "long_lived", "unknown"]
SCOPE_SOURCES = ["explicit", "implicit_default", "read-all", "write-all", "declared", "unknown"]
RESOURCE_KINDS = ["host", "package", "image", "environment", "branch", "trigger", "role", "namespace", "cloud_resource"]
CLASSES = ["G1", "G2", "G3", "G4", "G5", "G6", "G7", "G8"]
SEVERITIES = ["critical", "warning", "note", "off"]
CHANGES = ["introduced", "unchanged", "removed"]

# Format classes for inline secrets: a closed enumeration, never the value.
FORMAT_CLASSES = [
    "anthropic_key",
    "openai_key",
    "github_pat_classic",
    "github_pat_fine_grained",
    "github_oauth_token",
    "github_app_token",
    "aws_access_key_id",
    "slack_token",
    "slack_webhook_url",
    "stripe_secret_key",
    "google_api_key",
    "gitlab_pat",
    "npm_token",
    "pypi_token",
    "huggingface_token",
    "sendgrid_key",
    "jwt",
    "private_key_pem",
    "bearer_literal",
    "basic_auth_literal",
    "connection_string_with_password",
    "k8s_secret_data_base64",
    "generic_literal",
]

_NAME = {"type": "string", "minLength": 1, "maxLength": 512}
_PATH = {"type": "string", "minLength": 1, "maxLength": 1024}

_DEFS: dict[str, Any] = {
    "component": {
        "type": "object",
        "additionalProperties": False,
        "required": ["id", "kind", "name", "file"],
        "properties": {
            "id": _NAME,
            "kind": {"enum": COMPONENT_KINDS},
            "name": _NAME,
            "file": _PATH,
        },
    },
    "format": {
        "type": "object",
        "additionalProperties": False,
        "required": ["class"],
        "properties": {
            "class": {"enum": FORMAT_CLASSES},
            # Only a prefix taken verbatim from grantlock.model.FORMAT_TABLE.
            "prefix": {"type": ["string", "null"], "maxLength": 16},
        },
    },
    "credential": {
        "type": "object",
        "additionalProperties": False,
        "required": ["provider", "type", "name", "storage", "format"],
        "properties": {
            "provider": {"type": "string", "pattern": "^[a-z0-9_.-]+$"},
            "type": {"enum": CREDENTIAL_TYPES},
            "name": _NAME,
            "storage": {"enum": STORAGE_CLASSES},
            "format": {"oneOf": [{"type": "null"}, {"$ref": "#/$defs/format"}]},
        },
    },
    "resource": {
        "type": "object",
        "additionalProperties": False,
        "required": ["kind", "value"],
        "properties": {"kind": {"enum": RESOURCE_KINDS}, "value": _NAME},
    },
    "owner": {
        "oneOf": [
            {"type": "null"},
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["source", "owners", "rule", "line"],
                "properties": {
                    "source": {"enum": ["codeowners", "declared"]},
                    "owners": {"type": "array", "items": _NAME, "minItems": 1},
                    "rule": {"type": "string", "maxLength": 1024},
                    "line": {"type": ["integer", "null"]},
                },
            },
        ]
    },
    "context": {
        "type": "object",
        "additionalProperties": False,
        "required": ["federation_available", "reason"],
        "properties": {
            "federation_available": {"type": "boolean"},
            "reason": {"type": ["string", "null"], "maxLength": 512},
        },
    },
    "evidence": {
        "type": "object",
        "additionalProperties": False,
        "required": ["file", "line", "locator"],
        "properties": {
            "file": _PATH,
            "line": {"type": ["integer", "null"]},
            "locator": {"type": "string", "maxLength": 1024},
        },
    },
    "entry": {
        "type": "object",
        "additionalProperties": False,
        "required": [
            "identity_id",
            "component",
            "credential",
            "scopes",
            "scopes_known",
            "scope_source",
            "resources",
            "owner",
            "lifespan",
            "context",
        ],
        "properties": {
            "identity_id": _NAME,
            "component": {"$ref": "#/$defs/component"},
            "credential": {"$ref": "#/$defs/credential"},
            "scopes": {"type": "array", "items": _NAME, "uniqueItems": True},
            "scopes_known": {"type": "boolean"},
            "scope_source": {"enum": SCOPE_SOURCES},
            "resources": {"type": "array", "items": {"$ref": "#/$defs/resource"}},
            "owner": {"$ref": "#/$defs/owner"},
            "lifespan": {"enum": LIFESPANS},
            "context": {"$ref": "#/$defs/context"},
            "evidence": {"type": "array", "items": {"$ref": "#/$defs/evidence"}},
        },
    },
    "generator": {
        "type": "object",
        "additionalProperties": False,
        "required": ["name", "version"],
        "properties": {"name": {"const": "grantlock"}, "version": {"type": "string"}},
    },
    "warning": {
        "type": "object",
        "additionalProperties": False,
        "required": ["file", "message"],
        "properties": {"file": _PATH, "message": {"type": "string", "maxLength": 512}},
    },
}

INVENTORY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:grantlock:schema:inventory:1.0",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "document", "generator", "entries", "warnings"],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "document": {"const": DOC_INVENTORY},
        "generator": {"$ref": "#/$defs/generator"},
        "entries": {"type": "array", "items": {"$ref": "#/$defs/entry"}},
        "warnings": {"type": "array", "items": {"$ref": "#/$defs/warning"}},
    },
    "$defs": _DEFS,
}

LOCK_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:grantlock:schema:lock:1.0",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "document", "generator", "entries"],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "document": {"const": DOC_LOCK},
        "generator": {"$ref": "#/$defs/generator"},
        "entries": {"type": "array", "items": {"$ref": "#/$defs/entry"}},
    },
    "$defs": _DEFS,
}

_FINDING = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "finding_id",
        "class",
        "title",
        "severity",
        "change",
        "identity_id",
        "component",
        "file",
        "line",
        "production",
        "details",
        "message",
    ],
    "properties": {
        "finding_id": _NAME,
        "class": {"enum": CLASSES},
        "title": {"type": "string", "maxLength": 128},
        "severity": {"enum": ["critical", "warning", "note"]},
        "change": {"enum": CHANGES},
        "identity_id": _NAME,
        "component": {"$ref": "#/$defs/component"},
        "file": _PATH,
        "line": {"type": ["integer", "null"]},
        "production": {
            "type": "object",
            "additionalProperties": False,
            "required": ["value", "evidence"],
            "properties": {
                "value": {"type": "boolean"},
                "evidence": {"type": "array", "items": {"type": "string", "maxLength": 512}},
            },
        },
        "details": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "added_scopes": {"type": "array", "items": _NAME},
                "scope_source_change": {"type": "array", "items": {"enum": SCOPE_SOURCES}},
                "wildcard_reasons": {"type": "array", "items": {"type": "string", "maxLength": 512}},
                "format": {"$ref": "#/$defs/format"},
                "shared_with": {"type": "array", "items": _NAME},
                "federation_reason": {"type": ["string", "null"], "maxLength": 512},
                "previous_storage": {"enum": STORAGE_CLASSES + [None]},
            },
        },
        "message": {"type": "string", "maxLength": 1024},
    },
}

_DRIFT = {
    "type": "object",
    "additionalProperties": False,
    "required": ["kind", "identity_id", "component_id"],
    "properties": {
        "kind": {
            "enum": [
                "binding_added",
                "binding_removed",
                "scopes_removed",
                "scopes_became_known",
                "storage_changed",
                "owner_changed",
                "resources_changed",
                "lifespan_changed",
            ]
        },
        "identity_id": _NAME,
        "component_id": _NAME,
    },
}

FINDINGS_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:grantlock:schema:findings:1.0",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "document", "generator", "summary", "findings", "drift"],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "document": {"const": DOC_FINDINGS},
        "generator": {"$ref": "#/$defs/generator"},
        "summary": {
            "type": "object",
            "additionalProperties": False,
            "required": ["critical", "warning", "note", "total", "by_class", "exit_code", "lock_in_sync"],
            "properties": {
                "critical": {"type": "integer", "minimum": 0},
                "warning": {"type": "integer", "minimum": 0},
                "note": {"type": "integer", "minimum": 0},
                "total": {"type": "integer", "minimum": 0},
                "by_class": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {c: {"type": "integer", "minimum": 0} for c in CLASSES},
                },
                "exit_code": {"enum": [0, 1]},
                "lock_in_sync": {"type": "boolean"},
            },
        },
        "findings": {"type": "array", "items": _FINDING},
        "drift": {"type": "array", "items": _DRIFT},
    },
    "$defs": _DEFS,
}

_SEV_PAIR = {
    "type": "object",
    "additionalProperties": False,
    "required": ["production", "non_production"],
    "properties": {"production": {"enum": SEVERITIES}, "non_production": {"enum": SEVERITIES}},
}

POLICY_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:grantlock:schema:policy:1.0",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "document"],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "document": {"const": DOC_POLICY},
        "severity": {
            "type": "object",
            "additionalProperties": False,
            "properties": {c: _SEV_PAIR for c in CLASSES},
        },
        "production_patterns": {"type": "array", "items": {"type": "string", "maxLength": 256}},
        "strict_recorded_g3": {
            "type": "boolean",
            "description": "true: a production G3 already recorded in grantlock.json stays critical (D-010 opt-out)",
        },
        "declared_owners": {
            "type": "object",
            "description": "component id (exact) -> list of owners",
            "additionalProperties": {"type": "array", "items": _NAME, "minItems": 1},
        },
    },
}

_COUNT_MAP = {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}}
_CONTROL = {
    "type": "object", "additionalProperties": False, "required": ["framework", "control", "title"],
    "properties": {"framework": {"enum": ["NIST SP 800-53 Rev. 5", "SOC 2 TSC 2017"]},
                   "control": {"type": "string", "maxLength": 32}, "title": {"type": "string", "maxLength": 128}},
}

EVIDENCE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "urn:grantlock:schema:evidence:1.0",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "document", "generator", "disclaimer", "inputs", "inventory_summary",
                 "findings_summary", "findings", "lock_history", "control_mapping"],
    "properties": {
        "schema_version": {"const": SCHEMA_VERSION},
        "document": {"const": DOC_EVIDENCE},
        "generator": {"$ref": "#/$defs/generator"},
        "disclaimer": {"type": "string", "maxLength": 1024},
        "inputs": {
            "type": "object", "additionalProperties": False,
            "required": ["schema_versions", "policy", "lock_in_sync"],
            "properties": {
                "schema_versions": {"type": "object", "additionalProperties": {"type": "string"}},
                "policy": {"type": "object"},
                "lock_in_sync": {"type": "boolean"},
            },
        },
        "inventory_summary": {
            "type": "object", "additionalProperties": False,
            "required": ["identities", "bindings", "by_component_kind", "by_storage", "by_lifespan", "owned_bindings", "unowned_bindings"],
            "properties": {
                "identities": {"type": "integer", "minimum": 0}, "bindings": {"type": "integer", "minimum": 0},
                "by_component_kind": _COUNT_MAP, "by_storage": _COUNT_MAP, "by_lifespan": _COUNT_MAP,
                "owned_bindings": {"type": "integer", "minimum": 0}, "unowned_bindings": {"type": "integer", "minimum": 0},
            },
        },
        "findings_summary": {
            "type": "object", "additionalProperties": False, "required": ["by_class", "by_severity", "exit_code"],
            "properties": {"by_class": _COUNT_MAP, "by_severity": _COUNT_MAP, "exit_code": {"enum": [0, 1]}},
        },
        "findings": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["finding_id", "class", "title", "severity", "change", "identity_id", "component_id", "file", "line",
                         "production_evidence", "rationale", "controls"],
            "properties": {
                "finding_id": _NAME, "class": {"enum": CLASSES}, "title": {"type": "string", "maxLength": 128},
                "severity": {"enum": ["critical", "warning", "note"]}, "change": {"enum": CHANGES},
                "identity_id": _NAME, "component_id": _NAME, "file": _PATH, "line": {"type": ["integer", "null"]},
                "production_evidence": {"type": "array", "items": {"type": "string", "maxLength": 512}},
                "rationale": {"type": "string", "maxLength": 1024},
                "controls": {"type": "array", "items": {"type": "string", "maxLength": 32}},
            }}},
        "lock_history": {
            "oneOf": [{"type": "null"}, {
                "type": "object", "additionalProperties": False,
                "required": ["previous_bindings", "current_bindings", "identities_added", "identities_removed",
                             "bindings_added", "bindings_removed", "bindings_with_scope_changes"],
                "properties": {k: {"type": "integer", "minimum": 0} for k in (
                    "previous_bindings", "current_bindings", "identities_added", "identities_removed",
                    "bindings_added", "bindings_removed", "bindings_with_scope_changes")},
            }]
        },
        "control_mapping": {
            "type": "object", "additionalProperties": False, "required": ["nature", "by_class"],
            "properties": {
                "nature": {"type": "string", "maxLength": 512},
                "by_class": {"type": "object", "additionalProperties": False,
                             "properties": {c: {"type": "array", "items": _CONTROL} for c in CLASSES}},
            },
        },
    },
    "$defs": _DEFS,
}

_VALIDATORS = {
    DOC_INVENTORY: Draft202012Validator(INVENTORY_SCHEMA),
    DOC_LOCK: Draft202012Validator(LOCK_SCHEMA),
    DOC_FINDINGS: Draft202012Validator(FINDINGS_SCHEMA),
    DOC_POLICY: Draft202012Validator(POLICY_SCHEMA),
    DOC_EVIDENCE: Draft202012Validator(EVIDENCE_SCHEMA),
}


class SchemaError(ValueError):
    """Raised when a document does not conform to its versioned schema."""


def validation_errors(doc: Any, document_type: str) -> list[str]:
    validator = _VALIDATORS[document_type]
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '<root>'}: {e.message}" for e in errors]


def validate(doc: Any, document_type: str) -> None:
    errs = validation_errors(doc, document_type)
    if errs:
        raise SchemaError(f"{document_type} schema violation: " + "; ".join(errs[:5]))


def schema_for(document_type: str) -> dict[str, Any]:
    return copy.deepcopy(
        {
            DOC_INVENTORY: INVENTORY_SCHEMA,
            DOC_LOCK: LOCK_SCHEMA,
            DOC_FINDINGS: FINDINGS_SCHEMA,
            DOC_POLICY: POLICY_SCHEMA,
            DOC_EVIDENCE: EVIDENCE_SCHEMA,
        }[document_type]
    )
