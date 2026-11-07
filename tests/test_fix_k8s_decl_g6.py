"""Fix round Step 3 (D-042): G6 on the declaration side (ServiceAccount / Secret) when no workload uses the static key."""

from repo_builder import of_class, run_check, write
from repo_builder2 import base_repo2

SA_FED = """apiVersion: v1
kind: ServiceAccount
metadata:
  name: exporter
  namespace: jobs
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/exporter
"""
SA_STATIC = """apiVersion: v1
kind: ServiceAccount
metadata:
  name: exporter
  namespace: jobs
---
apiVersion: v1
kind: Secret
metadata:
  name: exporter-aws
  namespace: jobs
type: Opaque
stringData:
  AWS_ACCESS_KEY_ID: ""
  AWS_SECRET_ACCESS_KEY: ""
"""
WORKLOAD = """apiVersion: batch/v1
kind: Job
metadata:
  name: export
  namespace: jobs
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: export
          image: ghcr.io/acme/export:1
          env:
            - name: AWS_ACCESS_KEY_ID
              valueFrom:
                secretKeyRef: {name: exporter-aws, key: AWS_ACCESS_KEY_ID}
"""


def test_federation_removed_and_static_secret_declared(tmp_path):
    repo = base_repo2(tmp_path, {"deploy/exporter.yaml": SA_FED})
    write(repo, {"deploy/exporter.yaml": SA_STATIC})
    f = run_check(repo)
    comps = {(g["component"]["name"], g["file"]) for g in of_class(f, "G6")}
    assert ("exporter", "deploy/exporter.yaml") in comps        # the ServiceAccount where federation was removed
    assert ("exporter-aws", "deploy/exporter.yaml") in comps    # the static-key Secret declaration


def test_used_static_secret_reports_only_at_the_workload(tmp_path):
    """No double counting: when a workload uses the key, G6 stays on the workload as before."""
    repo = base_repo2(tmp_path, {"deploy/exporter.yaml": SA_FED})
    write(repo, {"deploy/exporter.yaml": SA_STATIC, "deploy/job.yaml": WORKLOAD})
    g6 = of_class(run_check(repo), "G6")
    assert {g["component"]["name"] for g in g6} == {"export"}


def test_non_cloud_secret_is_not_G6(tmp_path):
    repo = base_repo2(tmp_path)
    write(repo, {"deploy/misc.yaml": SA_STATIC.replace("AWS_ACCESS_KEY_ID", "SLACK_BOT_TOKEN").replace("AWS_SECRET_ACCESS_KEY", "NOTION_TOKEN")})
    assert of_class(run_check(repo), "G6") == []


def test_federated_sa_is_not_linked(tmp_path):
    repo = base_repo2(tmp_path)
    both = SA_FED + "---\n" + SA_STATIC.split("---\n", 1)[1]
    write(repo, {"deploy/exporter.yaml": both})
    g6 = of_class(run_check(repo), "G6")
    assert {g["component"]["name"] for g in g6} == {"exporter-aws"}  # Secret only; the SA is still federated
