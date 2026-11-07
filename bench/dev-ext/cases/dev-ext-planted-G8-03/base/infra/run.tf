# support-copilot: IAM for the agent runtime and CI deploys.

resource "google_cloud_run_v2_service" "runtime" {
  name     = "support-copilot"
  location = "us-central1"
  template {
    service_account = google_service_account.runtime.email
    containers {
      image = "ghcr.io/cyberdyne/support-copilot:2.6.7"
    }
  }
}
