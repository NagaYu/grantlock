"""Fix round Step 1 (D-040): Roles / ClusterRoles not referenced by any binding are identities of their own."""

import grantlock
from repo_builder import of_class, run_check, write
from repo_builder2 import base_repo2

UNBOUND = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sync-controller
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: hook-reader
  namespace: agents
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
"""

BIND_SYNC = """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sync-controller
subjects:
  - kind: ServiceAccount
    name: agent
    namespace: agents
roleRef:
  kind: ClusterRole
  name: sync-controller
  apiGroup: rbac.authorization.k8s.io
"""


def test_unbound_roles_are_in_the_inventory(tmp_path):
    repo = base_repo2(tmp_path, {"deploy/unbound.yaml": UNBOUND})
    inv = grantlock.scan(repo)
    ids = {(e["identity_id"], e["component"]["name"], e["component"]["kind"]) for e in inv["entries"]}
    assert ("kubernetes:clusterrole:sync-controller", "sync-controller", "k8s_rbac") in ids
    assert ("kubernetes:role:agents/hook-reader", "hook-reader", "k8s_rbac") in ids


def test_unbound_role_widened_is_G2(tmp_path):
    repo = base_repo2(tmp_path, {"deploy/unbound.yaml": UNBOUND})
    write(repo, {"deploy/unbound.yaml": UNBOUND.replace('resources: ["configmaps"]\n    verbs: ["get"]',
                                                        'resources: ["configmaps", "secrets"]\n    verbs: ["get", "create"]')})
    f = run_check(repo)
    g2 = of_class(f, "G2")
    assert [(g["component"]["name"], g["file"]) for g in g2] == [("hook-reader", "deploy/unbound.yaml")]
    assert "rbac:ns:create:secrets" in g2[0]["details"]["added_scopes"]


def test_unbound_clusterrole_wildcard_is_G3(tmp_path):
    repo = base_repo2(tmp_path, {"deploy/unbound.yaml": UNBOUND})
    write(repo, {"deploy/unbound.yaml": UNBOUND.replace('apiGroups: ["apps"]\n    resources: ["deployments"]\n    verbs: ["get", "list", "watch"]',
                                                        'apiGroups: ["*"]\n    resources: ["*"]\n    verbs: ["*"]')})
    g3 = of_class(run_check(repo), "G3")
    assert [(g["component"]["name"], g["file"]) for g in g3] == [("sync-controller", "deploy/unbound.yaml")]


def test_bound_role_change_is_not_double_counted(tmp_path):
    """A bound role keeps the binding-based identity only: one G2 per subject, no role identity."""
    repo = base_repo2(tmp_path)
    inv = grantlock.scan(repo)
    assert not any(e["identity_id"].startswith(("kubernetes:role:", "kubernetes:clusterrole:")) for e in inv["entries"])
    from repo_builder2 import K8S_RBAC
    write(repo, {"deploy/rbac.yaml": K8S_RBAC.replace('verbs: ["get"]', 'verbs: ["*"]')})
    f = run_check(repo)
    assert len(of_class(f, "G2")) == 1 and len(of_class(f, "G3")) == 1


def test_binding_an_unbound_role_is_not_dormant(tmp_path):
    repo = base_repo2(tmp_path, {"deploy/unbound.yaml": UNBOUND})
    write(repo, {"deploy/bind.yaml": BIND_SYNC})
    f = run_check(repo)
    assert of_class(f, "G8") == []  # the role still exists; it just became bound
    assert [g["component"]["name"] for g in of_class(f, "G2")] == ["sync-controller"]  # SA gains its rules (D-031)
