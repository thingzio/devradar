# Triggers the daily scan job via the Cloud Run Admin API. Uses a dedicated SA
# granted run.invoker on the job (see iam.tf).
resource "google_cloud_scheduler_job" "scan" {
  name      = "${var.prefix}-scan-scheduled"
  project   = var.project_id
  region    = var.region
  schedule  = var.scan_schedule
  time_zone = "UTC"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.scan.name}:run"

    oauth_token {
      service_account_email = google_service_account.scheduler.email
    }
  }

  depends_on = [google_project_service.default]
}
