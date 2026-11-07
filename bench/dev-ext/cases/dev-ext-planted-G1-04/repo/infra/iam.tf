# data-analyst-agent: IAM for the agent runtime and CI deploys.

resource "google_service_account" "runtime" {
  account_id   = "data-analyst-agent"
  display_name = "data-analyst-agent runtime"
}

resource "google_project_iam_member" "runtime_logs" {
  project = "umbrella-data-analyst-agent"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_secrets" {
  project = "umbrella-data-analyst-agent"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "data-analyst-agent"
  attribute_condition                = "assertion.repository == \"umbrella/data-analyst-agent\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
