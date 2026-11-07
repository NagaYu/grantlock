# support-copilot: エージェント実行環境と CI デプロイ用の IAM。

resource "google_service_account" "runtime" {
  account_id   = "support-copilot"
  display_name = "support-copilot runtime"
}

resource "google_project_iam_member" "runtime_logs" {
  project = "initech-support-copilot"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_secrets" {
  project = "initech-support-copilot"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "support-copilot"
  attribute_condition                = "assertion.repository == \"initech/support-copilot\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
