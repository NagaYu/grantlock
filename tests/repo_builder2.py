"""Multi-surface throwaway repos for Phase 2 integration tests."""

from pathlib import Path

from repo_builder import relock, write  # noqa: F401  (re-exported)

CODEOWNERS = """/compose.yaml   @acme/platform
/deploy/        @acme/platform
/infra/         @acme/infra
"""

COMPOSE = """services:
  agent:
    image: ghcr.io/acme/agent:1.0
    environment:
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
      LOG_LEVEL: info
  worker:
    image: ghcr.io/acme/worker:1.0
    environment:
      SLACK_BOT_TOKEN: ${SLACK_BOT_TOKEN}
"""

K8S_SA = """apiVersion: v1
kind: ServiceAccount
metadata:
  name: agent
  namespace: agents
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/agent
"""

K8S_RBAC = """apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: agent-reader
  namespace: agents
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: agent-reader
  namespace: agents
subjects:
  - kind: ServiceAccount
    name: agent
    namespace: agents
roleRef:
  kind: Role
  name: agent-reader
  apiGroup: rbac.authorization.k8s.io
"""

K8S_DEPLOY = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent
  namespace: agents
spec:
  template:
    spec:
      serviceAccountName: agent
      containers:
        - name: agent
          image: ghcr.io/acme/agent:1.0
          env:
            - name: OPENAI_API_KEY
              valueFrom:
                secretKeyRef: {name: llm-keys, key: OPENAI_API_KEY}
"""

TF = """resource "aws_iam_role" "agent" {
  name               = "agent"
  assume_role_policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "sts:AssumeRole" }] })
}

resource "aws_iam_role_policy" "agent" {
  role   = aws_iam_role.agent.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = ["arn:aws:s3:::agent-data/*"] }]
  })
}

resource "aws_lambda_function" "agent" {
  function_name = "agent"
  role          = aws_iam_role.agent.arn
}
"""

BASE2 = {
    ".github/CODEOWNERS": CODEOWNERS,
    "compose.yaml": COMPOSE,
    "deploy/serviceaccount.yaml": K8S_SA,
    "deploy/rbac.yaml": K8S_RBAC,
    "deploy/deployment.yaml": K8S_DEPLOY,
    "infra/main.tf": TF,
}


def base_repo2(tmp_path: Path, files: dict | None = None) -> Path:
    repo = tmp_path / "repo2"
    repo.mkdir()
    write(repo, dict(BASE2, **(files or {})))
    relock(repo)
    return repo
