# sales-ops-agent

sales-ops-agent は globex の devex チームが運用する AI エージェントサービスです。

- `compose.yaml`: ローカル開発用スタック
- `deploy/k8s/`: Kubernetes マニフェスト
- `infra/`: クラウド IAM の Terraform

認証情報は実行時に注入します（Docker secrets、External Secrets 管理の Kubernetes Secret、ワークロード ID）。
