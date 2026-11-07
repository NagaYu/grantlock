# billing-concierge: IAM for the agent runtime and CI deploys.

resource "google_cloud_run_v2_service" "runtime" {
  name     = "billing-concierge"
  location = "us-central1"
  template {
    service_account = google_service_account.runtime.email
    containers {
      image = "ghcr.io/initech/billing-concierge:3.5.2"
    }
  }
}

resource "google_cloud_run_v2_service" "admin_ui" {
  name     = "billing-concierge-admin"
  location = "us-central1"
  template {
    service_account = google_service_account.runtime.email
    containers {
      image = "ghcr.io/initech/billing-concierge:3.5.2"
    }
  }
}
