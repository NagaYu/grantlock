# sales-ops-agent: IAM for the agent runtime and CI deploys.

resource "google_cloud_run_v2_service" "runtime" {
  name     = "sales-ops-agent"
  location = "us-central1"
  template {
    service_account = google_service_account.runtime.email
    containers {
      image = "ghcr.io/initech/sales-ops-agent:2.8.1"
    }
  }
}
