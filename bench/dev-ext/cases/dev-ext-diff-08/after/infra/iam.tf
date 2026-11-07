# sales-ops-agent: エージェント実行環境と CI デプロイ用の IAM。

resource "google_service_account" "runtime" {
  account_id   = "sales-ops-agent"
  display_name = "sales-ops-agent runtime"
}

resource "google_project_iam_member" "runtime_logs" {
  project = "hooli-sales-ops-agent"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_secrets" {
  project = "hooli-sales-ops-agent"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "sales-ops-agent"
  attribute_condition                = "assertion.repository == \"hooli/sales-ops-agent\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
