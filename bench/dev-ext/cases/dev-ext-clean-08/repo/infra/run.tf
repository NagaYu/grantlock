# support-copilot: エージェント実行環境と CI デプロイ用の IAM。

resource "google_cloud_run_v2_service" "runtime" {
  name     = "support-copilot"
  location = "us-central1"
  template {
    service_account = google_service_account.runtime.email
    containers {
      image = "ghcr.io/initech/support-copilot:3.2.9"
    }
  }
}
