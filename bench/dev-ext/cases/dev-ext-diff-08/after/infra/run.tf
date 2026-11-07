# sales-ops-agent: エージェント実行環境と CI デプロイ用の IAM。

resource "google_cloud_run_v2_service" "runtime" {
  name     = "sales-ops-agent"
  location = "us-central1"
  template {
    service_account = google_service_account.runtime.email
    containers {
      image = "ghcr.io/hooli/sales-ops-agent:4.0.2"
    }
  }
}
