# qa-pilot: エージェント実行環境と CI デプロイ用の IAM。

resource "google_cloud_run_v2_service" "runtime" {
  name     = "qa-pilot"
  location = "us-central1"
  template {
    service_account = google_service_account.runtime.email
    containers {
      image = "ghcr.io/wayne-ent/qa-pilot:2.3.7"
    }
  }
}
