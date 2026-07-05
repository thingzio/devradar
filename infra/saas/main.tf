locals {
  # Shared infra references (from variables, not remote state — matches siblings).
  vpc_id        = var.vpc_id
  subnet_id     = var.subnet_id
  db_connection = var.db_connection_name

  image_base = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"

  # Service-specific APIs. The shared infra (thingzio/infra) already enables
  # compute, sqladmin, servicenetworking, monitoring, iam, etc.
  services = [
    "artifactregistry.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "storage.googleapis.com",
    "iam.googleapis.com",
  ]
}

resource "google_project_service" "default" {
  for_each = toset(local.services)
  project  = var.project_id
  service  = each.value
}

data "google_project" "default" {
  project_id = var.project_id
}
