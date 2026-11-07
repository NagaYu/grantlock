# triage-agent: IAM for the agent runtime and CI deploys.

resource "google_service_account" "runtime" {
  account_id   = "triage-agent"
  display_name = "triage-agent runtime"
}

resource "google_project_iam_member" "runtime_logs" {
  project = "stark-labs-triage-agent"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_secrets" {
  project = "stark-labs-triage-agent"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "triage-agent"
  attribute_condition                = "assertion.repository == \"stark-labs/triage-agent\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_key" "runtime" {
  service_account_id = google_service_account.runtime.name
}
