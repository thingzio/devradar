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
    "roles/monitoring.metricWriter", # write app metrics
    "roles/monitoring.viewer",       # read time series for the admin /metrics page
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

# Delivery has a separate identity: database connectivity and structured logs
# only. Secret access is granted per-secret in secrets.tf.
resource "google_service_account" "delivery" {
  account_id   = "${var.prefix}-delivery"
  display_name = "DevRadar email delivery runtime"
  project      = var.project_id
}

locals {
  delivery_roles = [
    "roles/cloudsql.client",
    "roles/logging.logWriter",
  ]
}

resource "google_project_iam_member" "delivery" {
  for_each = toset(local.delivery_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.delivery.email}"
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
  attribute_condition = "assertion.sub == 'repo:${var.git_repo}:environment:saas'"

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
  member             = "principal://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/subject/repo:${var.git_repo}:environment:saas"
}

resource "google_artifact_registry_repository_iam_member" "deployer_images" {
  project    = var.project_id
  location   = google_artifact_registry_repository.images.location
  repository = google_artifact_registry_repository.images.repository_id
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_cloud_run_v2_service_iam_member" "deployer_serve" {
  project  = var.project_id
  location = google_cloud_run_v2_service.serve.location
  name     = google_cloud_run_v2_service.serve.name
  role     = "roles/run.admin"
  member   = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_cloud_run_v2_job_iam_member" "deployer_scan" {
  project  = var.project_id
  location = google_cloud_run_v2_job.scan.location
  name     = google_cloud_run_v2_job.scan.name
  role     = "roles/run.admin"
  member   = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_cloud_run_v2_job_iam_member" "deployer_delivery" {
  project  = var.project_id
  location = google_cloud_run_v2_job.delivery.location
  name     = google_cloud_run_v2_job.delivery.name
  role     = "roles/run.admin"
  member   = "serviceAccount:${google_service_account.deployer.email}"
}

# Synchronous gcloud Run updates poll location-scoped long-running operations.
# Resource-level Run admin grants do not cover the operation resource.
resource "google_project_iam_custom_role" "cloud_run_operation_viewer" {
  role_id     = "devradarCloudRunOperationViewer"
  title       = "DevRadar Cloud Run operation viewer"
  description = "Poll Cloud Run deployment operations"
  project     = var.project_id
  permissions = ["run.operations.get"]
}

resource "google_project_iam_member" "deployer_cloud_run_operations" {
  project = var.project_id
  role    = google_project_iam_custom_role.cloud_run_operation_viewer.id
  member  = "serviceAccount:${google_service_account.deployer.email}"
}

# Cloud Scheduler does not expose job resource attributes to IAM Conditions, so
# this role must be project-scoped. It can only read and pause/resume jobs; it
# cannot create, delete, run, or change schedules/targets. Terraform remains the
# scheduler configuration owner.
resource "google_project_iam_custom_role" "delivery_scheduler_deployer" {
  role_id     = "devradarDeliverySchedulerDeploy"
  title       = "DevRadar delivery scheduler deploy control"
  description = "Read and pause/resume Cloud Scheduler jobs during safe deploys"
  project     = var.project_id
  permissions = [
    "cloudscheduler.jobs.enable",
    "cloudscheduler.jobs.get",
    "cloudscheduler.jobs.pause",
  ]
}

resource "google_project_iam_member" "deployer_delivery_scheduler" {
  project = var.project_id
  role    = google_project_iam_custom_role.delivery_scheduler_deployer.id
  member  = "serviceAccount:${google_service_account.deployer.email}"
}

# Deployer may act as the runtime SA (required to deploy Cloud Run revisions).
resource "google_service_account_iam_member" "deployer_run_sa" {
  service_account_id = google_service_account.run.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_service_account_iam_member" "deployer_delivery_sa" {
  service_account_id = google_service_account.delivery.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deployer.email}"
}

# --- Cloud Scheduler triggers bounded jobs ---

# Dedicated SA for the scheduler to invoke jobs, with per-job grants below.
resource "google_service_account" "scheduler" {
  account_id   = "${var.prefix}-scheduler"
  display_name = "DevRadar job scheduler"
  project      = var.project_id
}

resource "google_cloud_run_v2_job_iam_member" "scheduler_invoke_scan" {
  name     = google_cloud_run_v2_job.scan.name
  location = var.region
  project  = var.project_id
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}

resource "google_cloud_run_v2_job_iam_member" "scheduler_invoke_delivery" {
  name     = google_cloud_run_v2_job.delivery.name
  location = var.region
  project  = var.project_id
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.scheduler.email}"
}
