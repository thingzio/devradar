output "service_url" {
  description = "Ingest API + UI Cloud Run service URL"
  value       = google_cloud_run_v2_service.serve.uri
}

output "scan_job" {
  description = "Daily scan Cloud Run Job name"
  value       = google_cloud_run_v2_job.scan.name
}

output "service_account_email" {
  description = "Runtime service account (serve + scan)"
  value       = google_service_account.run.email
}

output "sbom_bucket" {
  description = "GCS bucket for stored SBOM bytes"
  value       = google_storage_bucket.sboms.name
}

output "image_repo" {
  description = "Artifact Registry repository path"
  value       = local.image_base
}

output "ar_repo" {
  description = "Artifact Registry repository ID"
  value       = google_artifact_registry_repository.images.repository_id
}

output "deployer_sa" {
  description = "GitHub Actions deployer service account email"
  value       = google_service_account.deployer.email
}

output "wif_provider" {
  description = "Workload Identity Federation provider for GitHub Actions"
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "db_user" {
  description = "DevRadar's DB user in the shared instance"
  value       = google_sql_user.app.name
}
