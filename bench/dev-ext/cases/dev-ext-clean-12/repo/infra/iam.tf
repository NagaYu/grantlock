# repo-gardener: IAM for the agent runtime and CI deploys.

resource "google_service_account" "runtime" {
  account_id   = "repo-gardener"
  display_name = "repo-gardener runtime"
}

resource "google_project_iam_member" "runtime_logs" {
  project = "initech-repo-gardener"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_secrets" {
  project = "initech-repo-gardener"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "repo-gardener"
  attribute_condition                = "assertion.repository == \"initech/repo-gardener\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
