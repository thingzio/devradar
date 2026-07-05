# GCS bucket for stored SBOM bytes (content-addressed). DevRadar-owned — the
# shared infra's db-backup bucket is not for app data. Objects are small and
# retained (they are the audited source artifacts); no lifecycle expiry.
resource "google_storage_bucket" "sboms" {
  name          = "${var.prefix}-sboms"
  project       = var.project_id
  location      = var.region
  force_destroy = false

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = false
  }

  depends_on = [google_project_service.default]
}
