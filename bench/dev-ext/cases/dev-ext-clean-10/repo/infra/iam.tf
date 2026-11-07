# qa-pilot: IAM for the agent runtime and CI deploys.

resource "google_service_account" "runtime" {
  account_id   = "qa-pilot"
  display_name = "qa-pilot runtime"
}

resource "google_project_iam_member" "runtime_logs" {
  project = "soylent-qa-pilot"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_secrets" {
  project = "soylent-qa-pilot"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "qa-pilot"
  attribute_condition                = "assertion.repository == \"soylent/qa-pilot\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
