import base64
from pathlib import Path

from grantlock import model
from grantlock.parsers.k8s import build, load_objects, parse_k8s
from secret_guard import assert_no_secret_leak

FX = Path(__file__).parent / "fixtures" / "k8s"
SECRETS = [
    "sk-proj-FAKEk8sData000000000000000000000000000000000000000000T3BlbkFJ0000000000000000000000000000000000000000000000000000",
    "sk-ant-api03-FAKEk8sStringData0000000000000000000000000000000000000000000000000000000000000000000000000AA",
    "AKIAFAKEK8SSTATIC234",
    "FAKEk8sAwsSecret000000000000000000000000",
    "ghp_FAKEk8sLiteral00000000000000000000",
]


def _all():
    objs, warns = [], []
    for p in sorted(FX.rglob("*.y*ml")):
        o, w = load_objects(p.relative_to(FX).as_posix(), p.read_text())
        objs += o
        warns += w
    entries, w2 = build(objs)
    return entries, warns + w2


def _find(entries, identity, comp=None, kind=None):
    hits = [e for e in entries if e["identity_id"] == identity and (comp is None or e["component"]["name"] == comp)
            and (kind is None or e["component"]["kind"] == kind)]
    assert len(hits) == 1, (identity, comp, sorted({(e["identity_id"], e["component"]["name"]) for e in entries}))
    return hits[0]


def test_discovery_skips_non_k8s_and_warns_on_templates():
    entries, warnings = _all()
    files = {e["component"]["file"] for e in entries}
    assert "issue_template.yml" not in files
    assert any(w["file"] == "chart/templates/deployment.yaml" for w in warnings)


def test_secret_data_is_inline_but_never_decoded():
    entries, _ = _all()
    e = _find(entries, "openai:k8s-secret:agents/app-keys.OPENAI_API_KEY", "app-keys")
    assert e["component"]["kind"] == "k8s_secret"
    assert e["credential"]["storage"] == "inline"
    assert e["credential"]["format"] == {"class": "k8s_secret_data_base64", "prefix": None}
    s = _find(entries, "anthropic:k8s-secret:agents/app-keys.ANTHROPIC_API_KEY", "app-keys")
    assert s["credential"]["format"] == {"class": "anthropic_key", "prefix": "sk-ant-"}
    # empty / placeholder values are declarations, not inline values
    assert _find(entries, "unknown:k8s-secret:agents/app-keys.EMPTY_TOKEN", "app-keys")["credential"]["storage"] == "vault_ref"
    assert _find(entries, "unknown:k8s-secret:agents/app-keys.WEBHOOK_TOKEN", "app-keys")["credential"]["storage"] == "vault_ref"
    # sealed secrets are encrypted at rest
    assert _find(entries, "slack:k8s-secret:agents/slack.SLACK_BOT_TOKEN", "slack")["credential"]["storage"] == "vault_ref"


def test_no_secret_value_or_decoded_value_in_output():
    entries, warnings = _all()
    assert_no_secret_leak(entries, SECRETS)
    assert_no_secret_leak(warnings, SECRETS)
    encoded = base64.b64encode(SECRETS[0].encode()).decode()
    import json
    assert encoded not in json.dumps(entries)


def test_parser_never_decodes_base64():
    import inspect
    from grantlock.parsers import k8s
    src = inspect.getsource(k8s)
    assert "b64decode" not in src and "base64" not in src.replace("k8s_secret_data_base64", "").replace("base64-decoded", "")


def test_service_account_federation_annotation():
    entries, _ = _all()
    sa = _find(entries, "kubernetes:serviceaccount:agents/agent", "agent", "k8s_service_account")
    assert sa["component"]["kind"] == "k8s_service_account"
    assert sa["credential"]["storage"] == "federated"
    assert {"kind": "role", "value": "arn:aws:iam::111122223333:role/agent-runtime"} in sa["resources"]
    rep = _find(entries, "kubernetes:serviceaccount:agents/reporter", "reporter")
    assert rep["credential"]["storage"] == "vault_ref" and rep["lifespan"] == "ephemeral"


def test_rbac_resolution_and_wildcards():
    entries, _ = _all()
    reader = _find(entries, "kubernetes:serviceaccount:agents/agent", "agent-reader")
    assert reader["component"]["kind"] == "k8s_rbac" and reader["component"]["file"] == "deploy/rbac.yaml"
    assert reader["scopes"] == ["rbac:ns:get:configmaps", "rbac:ns:list:configmaps"]
    assert model.wildcard_reasons(reader["scopes"]) == []
    god = _find(entries, "kubernetes:serviceaccount:agents/reporter", "reporter-everything")
    assert god["scopes"] == ["rbac:cluster:*:*.*"]
    assert model.wildcard_reasons(god["scopes"])
    # binding to a built-in role not defined in the repo: component is the binding
    ops = _find(entries, "kubernetes:serviceaccount:platform/ops", "ops-admin")
    assert "role:cluster-admin" in ops["scopes"] and model.wildcard_reasons(ops["scopes"])
    # cluster-wide read on secrets is admin-level material
    sr = _find(entries, "kubernetes:serviceaccount:agents/agent", "secret-reader")
    assert any("secrets" in r for r in model.wildcard_reasons(sr["scopes"]))


def test_workload_consumers():
    entries, warnings = _all()
    dep = [e for e in entries if e["component"]["kind"] == "k8s_workload" and e["component"]["name"] == "agent"]
    ids = sorted(e["identity_id"] for e in dep)
    assert "kubernetes:serviceaccount:agents/agent" in ids
    assert "openai:k8s-secret:agents/app-keys.OPENAI_API_KEY" in ids  # secretKeyRef + envFrom merged
    assert "anthropic:k8s-secret:agents/app-keys.ANTHROPIC_API_KEY" in ids  # envFrom expands keys
    assert "unknown:k8s-secret:agents/regcred" in ids  # imagePullSecrets (secret not in repo)
    lit = _find(entries, "github:GITHUB_TOKEN", "agent")
    assert lit["credential"]["storage"] == "inline" and lit["credential"]["format"]["class"] == "github_pat_classic"
    assert not any("LOG_LEVEL" in i for i in ids)
    # shared secret key: Deployment and Pod both use the anthropic key (G5 material)
    users = sorted(e["component"]["name"] for e in entries
                   if e["identity_id"] == "anthropic:k8s-secret:agents/app-keys.ANTHROPIC_API_KEY" and e["component"]["kind"] == "k8s_workload")
    assert users == ["agent", "debug-shell"]


def test_static_key_secret_used_by_workload_is_g6_material():
    entries, _ = _all()
    aws = _find(entries, "aws:k8s-secret:agents/aws-static.AWS_ACCESS_KEY_ID", "nightly-report")
    assert aws["context"]["federation_available"] is True and "IRSA" in aws["context"]["reason"]
    assert aws["lifespan"] == "long_lived"
    tok = _find(entries, "kubernetes:sa-token:agents/reporter", "reporter-token")
    assert tok["lifespan"] == "long_lived" and tok["context"]["federation_available"] is True


def test_cronjob_pod_spec_and_namespace_resources():
    entries, _ = _all()
    cj = [e for e in entries if e["component"]["name"] == "nightly-report"]
    assert cj and all({"kind": "namespace", "value": "agents"} in e["resources"] for e in cj)
    assert all({"kind": "image", "value": "ghcr.io/acme/reporter:1.0.0"} in e["resources"] for e in cj)


def test_single_file_convenience_and_determinism():
    p = FX / "deploy" / "workloads.yaml"
    a = parse_k8s("deploy/workloads.yaml", p.read_text())
    assert a == parse_k8s("deploy/workloads.yaml", p.read_text())
    assert any("not defined in the repository" in w["message"] for w in a[1])


def test_garbage_does_not_crash():
    assert parse_k8s("x.yaml", "apiVersion: v1\nkind: [") [0] == []
    assert parse_k8s("x.yaml", "apiVersion: v1\nkind: Secret\n") == ([], [])  # no metadata.name
    assert parse_k8s("x.yaml", "just: text\n") == ([], [])
