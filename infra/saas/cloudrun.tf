# ── Ingest API + UI (serve) — pure-Go ko image, public, scales to zero ─────────
resource "google_cloud_run_v2_service" "serve" {
  name                = "${var.prefix}-serve"
  location            = var.region
  project             = var.project_id
  deletion_protection = false # TODO: set true after initial deploy

  template {
    service_account = google_service_account.run.email

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    vpc_access {
      network_interfaces {
        network    = local.vpc_id
        subnetwork = local.subnet_id
      }
      egress = "PRIVATE_RANGES_ONLY"
    }

    containers {
      # Bootstrap placeholder; CI (gcloud run deploy) sets the real image and
      # Terraform ignores it thereafter (see lifecycle block below).
      image = var.bootstrap_image

      ports {
        container_port = 8080
      }

      env {
        name = "DATABASE_URL"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.database_url.secret_id
            version = "latest"
          }
        }
      }

      env {
        name  = "BASE_URL"
        value = "https://${var.domain}"
      }

      env {
        name  = "DEVRADAR_SBOM_BUCKET"
        value = google_storage_bucket.sboms.name
      }

      env {
        name  = "EMAIL_FROM"
        value = var.email_from
      }

      # Magic-link sign-in (and later alerts).
      env {
        name = "SEND_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.send_api_key.secret_id
            version = "latest"
          }
        }
      }

      # GitHub OAuth sign-in. Client ID is public → plain env var; client secret
      # comes from Secret Manager. Both must be non-placeholder for the UI to
      # show the "Continue with GitHub" button (else it stays email-only).
      env {
        name  = "GITHUB_OAUTH_CLIENT_ID"
        value = var.github_oauth_client_id
      }

      env {
        name = "GITHUB_OAUTH_CLIENT_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.oauth_client_secret.secret_id
            version = "latest"
          }
        }
      }

      resources {
        limits = {
          cpu    = "1000m"
          memory = "512Mi"
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      startup_probe {
        http_get {
          path = "/health"
        }
        initial_delay_seconds = 2
        period_seconds        = 3
        failure_threshold     = 5
      }
    }

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [local.db_connection]
      }
    }
  }

  # CI owns the deployed image; Terraform owns the resource shape. Ignore the
  # image so `gcloud run deploy` from the release workflow is not reverted on the
  # next `terraform apply`.
  lifecycle {
    ignore_changes = [template[0].containers[0].image]
  }

  depends_on = [google_project_service.default]
}

resource "google_cloud_run_v2_service_iam_member" "serve_public" {
  name     = google_cloud_run_v2_service.serve.name
  location = var.region
  project  = var.project_id
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# ── Daily scan job — scanner image (grype/trivy/syft baked in), single task ────
resource "google_cloud_run_v2_job" "scan" {
  name                = "${var.prefix}-scan"
  location            = var.region
  project             = var.project_id
  deletion_protection = false # TODO: set true after initial deploy

  template {
    # v1 is single-instance (see IMPLEMENTATION.md "Concurrency"); one task per run.
    task_count  = 1
    parallelism = 1

    template {
      service_account = google_service_account.run.email
      timeout         = "5400s" # 90 min — headroom over the ~72 min corpus budget
      max_retries     = 1

      vpc_access {
        network_interfaces {
          network    = local.vpc_id
          subnetwork = local.subnet_id
        }
        egress = "PRIVATE_RANGES_ONLY"
      }

      containers {
        # Bootstrap placeholder; CI sets the real scan image (see lifecycle below).
        image = var.bootstrap_image

        env {
          name = "DATABASE_URL"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.database_url.secret_id
              version = "latest"
            }
          }
        }

        env {
          name  = "DEVRADAR_SBOM_BUCKET"
          value = google_storage_bucket.sboms.name
        }

        resources {
          limits = {
            cpu = "2000m"
            # Both scanners load a full vuln DB into memory: Grype's stays
            # resident while Trivy downloads + decompresses its own (~1GB+),
            # so peak usage exceeds 2Gi and the job was OOM-killed. 4Gi covers
            # both DBs plus the working set for a single SBOM scan.
            memory = "4Gi"
          }
        }

        volume_mounts {
          name       = "cloudsql"
          mount_path = "/cloudsql"
        }
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [local.db_connection]
        }
      }
    }
  }

  # CI owns the deployed image (nested template for jobs).
  lifecycle {
    ignore_changes = [template[0].template[0].containers[0].image]
  }

  depends_on = [google_project_service.default]
}
