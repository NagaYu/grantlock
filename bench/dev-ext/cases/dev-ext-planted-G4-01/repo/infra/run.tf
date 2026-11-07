# incident-bot: IAM for the agent runtime and CI deploys.

resource "google_cloud_run_v2_service" "runtime" {
  name     = "incident-bot"
  location = "us-central1"
  template {
    service_account = google_service_account.runtime.email
    containers {
      image = "ghcr.io/tyrell/incident-bot:4.15.2"
    }
  }
}
