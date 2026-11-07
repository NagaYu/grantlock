# billing-concierge: IAM for the agent runtime and CI deploys.

resource "google_service_account" "runtime" {
  account_id   = "billing-concierge"
  display_name = "billing-concierge runtime"
}

resource "google_project_iam_member" "runtime_logs" {
  project = "hooli-billing-concierge"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_secrets" {
  project = "hooli-billing-concierge"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "billing-concierge"
  attribute_condition                = "assertion.repository == \"hooli/billing-concierge\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
