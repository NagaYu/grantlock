# release-helper: IAM for the agent runtime and CI deploys.

resource "google_service_account" "runtime" {
  account_id   = "release-helper"
  display_name = "release-helper runtime"
}

resource "google_project_iam_member" "runtime_logs" {
  project = "globex-release-helper"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_secrets" {
  project = "globex-release-helper"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "release-helper"
  attribute_condition                = "assertion.repository == \"globex/release-helper\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
