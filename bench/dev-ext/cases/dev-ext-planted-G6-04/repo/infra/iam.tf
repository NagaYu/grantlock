# research-scout: IAM for the agent runtime and CI deploys.

resource "google_service_account" "runtime" {
  account_id   = "research-scout"
  display_name = "research-scout runtime"
}

resource "google_project_iam_member" "runtime_logs" {
  project = "soylent-research-scout"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_secrets" {
  project = "soylent-research-scout"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "research-scout"
  attribute_condition                = "assertion.repository == \"soylent/research-scout\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
