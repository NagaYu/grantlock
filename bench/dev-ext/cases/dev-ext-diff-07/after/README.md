# sales-ops-agent

sales-ops-agent is an AI agent service run by the initech ai-platform team.

- `compose.yaml`: local development stack
- `deploy/k8s/`: Kubernetes manifests
- `infra/`: Terraform for cloud IAM

Credentials are injected at runtime (Docker secrets, Kubernetes Secrets managed by External Secrets, workload identity).
