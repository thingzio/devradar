resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = "${var.prefix}-images"
  description   = "Container images for DevRadar (serve + scan)"
  format        = "DOCKER"
  project       = var.project_id
  mode          = "STANDARD_REPOSITORY"

  cleanup_policies {
    id     = "keep-recent"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }

  cleanup_policies {
    id     = "delete-old"
    action = "DELETE"
    condition {
      older_than = "604800s" # 7 days
    }
  }

  depends_on = [google_project_service.default]
}
