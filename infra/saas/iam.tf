# Runtime service account — used by both the serve service and the scan job.
resource "google_service_account" "run" {
  account_id   = "${var.prefix}-run"
  display_name = "DevRadar Cloud Run runtime"
  project      = var.project_id
}

locals {
  run_roles = [
    "roles/artifactregistry.reader",
    "roles/cloudsql.client",
    "roles/cloudsql.instanceUser",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
  ]
}

resource "google_project_iam_member" "run" {
  for_each = toset(local.run_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.run.email}"
}

# The run SA reads/writes SBOM bytes in DevRadar's own bucket (scoped to that
# bucket, not project-wide).
resource "google_storage_bucket_iam_member" "run_sboms" {
  bucket = google_storage_bucket.sboms.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.run.email}"
}

# --- GitHub Actions deploy via Workload Identity Federation (keyless) ---

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "gh-pool-${var.prefix}"
  display_name              = "GH Actions ${var.prefix}"
  project                   = var.project_id
  depends_on                = [google_project_service.default]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "gh-provider-${var.prefix}"
  display_name                       = "GH Provider ${var.prefix}"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
  }
  attribute_condition = "assertion.repository == '${var.git_repo}'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "deployer" {
  account_id   = "github-actions-${var.prefix}"
  display_name = "GitHub Actions deployer (${var.prefix})"
  project      = var.project_id
}

resource "google_service_account_iam_member" "deployer_wif" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.git_repo}"
}

locals {
  deployer_roles = [
    "roles/artifactregistry.writer",
    "roles/run.admin",
  ]
}

resource "google_project_iam_member" "deployer" {
  for_each = toset(local.deployer_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.deployer.email}"
}

# Deployer may act as the runtime SA (required to deploy Cloud Run revisions).
resource "google_service_account_iam_member" "deployer_run_sa" {
  service_account_id = google_service_account.run.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deployer.email}"
}

# --- Cloud Scheduler triggers the scan job ---

# Dedicated SA for the scheduler to invoke the scan job.
resource "google_service_account" "scheduler" {
  account_id   = "${var.prefix}-scheduler"
  display_name = "DevRadar scan scheduler"
  project      = var.project_id
}

resource "google_cloud_run_v2_job_iam_member" "scheduler_invoke_scan" {
  name     = google_cloud_run_v2_job.scan.name
  location = var.region
  project  = var.project_id
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}
