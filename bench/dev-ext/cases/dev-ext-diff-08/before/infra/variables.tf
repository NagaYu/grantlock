# sales-ops-agent: エージェント実行環境と CI デプロイ用の IAM。

variable "db_password" {
  type      = string
  sensitive = true
}
