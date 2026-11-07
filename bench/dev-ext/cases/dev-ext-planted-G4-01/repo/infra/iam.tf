# incident-bot: IAM for the agent runtime and CI deploys.

resource "google_service_account" "runtime" {
  account_id   = "incident-bot"
  display_name = "incident-bot runtime"
}

resource "google_project_iam_member" "runtime_logs" {
  project = "tyrell-incident-bot"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_project_iam_member" "runtime_secrets" {
  project = "tyrell-incident-bot"
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = "github"
  workload_identity_pool_provider_id = "incident-bot"
  attribute_condition                = "assertion.repository == \"tyrell/incident-bot\""
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}
