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

  # These APIs are shared across the platform (DevPulse/DevTrace enable most too).
  # Enabling an already-enabled API is a no-op, but the default deletion behavior
  # would DISABLE the API project-wide on `terraform destroy` — breaking the
  # sibling services. Never disable on destroy; leave APIs as we found them.
  disable_on_destroy         = false
  disable_dependent_services = false
}

data "google_project" "default" {
  project_id = var.project_id
}
