# triage-agent: IAM for the agent runtime and CI deploys.

resource "google_cloud_run_v2_service" "runtime" {
  name     = "triage-agent"
  location = "us-central1"
  template {
    service_account = google_service_account.runtime.email
    containers {
      image = "ghcr.io/globex/triage-agent:1.10.3"
    }
  }
}
