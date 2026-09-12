# Copyright 2026 Thingz LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

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
        name = "DEVRADAR_TOKEN_FLASH_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.token_flash_key.secret_id
            version = google_secret_manager_secret_version.token_flash_key.version
          }
        }
      }

      env {
        name = "DEVRADAR_DELIVERY_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.delivery_key.secret_id
            version = google_secret_manager_secret_version.delivery_key.version
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

      # Operator admin console allowlist. Emails only, not a secret — an empty
      # value keeps /admin returning 404 for everyone.
      env {
        name  = "DEVRADAR_ADMIN_USERS"
        value = var.admin_users
      }

      env {
        name  = "DEVRADAR_ACCOUNT_SHARING_ENABLED"
        value = tostring(var.account_sharing_enabled)
      }

      # Anthropic API key — optional. Powers the admin /metrics AI health summary
      # (and later narratives). Placeholder until set out-of-band; the claude
      # client treats the placeholder as unset and simply omits the summary.
      env {
        name = "ANTHROPIC_API_KEY"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.anthropic_api_key.secret_id
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

      # Readiness gate: /ready pings Postgres, so an instance is not routed
      # traffic until its DB is reachable (liveness /health stays dependency-free).
      startup_probe {
        http_get {
          path = "/ready"
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

  depends_on = [
    google_project_service.default,
    google_secret_manager_secret_iam_member.run_delivery_key,
    google_secret_manager_secret_iam_member.run_token_flash_key,
  ]
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
    # The scan loop is sequential and idempotent; one task avoids duplicate work.
    task_count  = 1
    parallelism = 1

    template {
      service_account = google_service_account.run.email
      # 90 min. A full-corpus pass (every SBOM due at once — cold start, an
      # outage longer than DEVRADAR_SCAN_MAX_AGE, a scanner DB bump, or a bulk
      # rescan) measured 16 min for 371 SBOMs on execution devradar-saas-scan-pm6fp
      # (2026-08-15): ~2.6s per SBOM across both scanners, 18% of this budget.
      # The timeout is not crossed until ~2,080 SBOMs. An earlier comment here
      # estimated "~72 min" and was wrong by 4.5x — do not re-derive this from
      # guesswork; see docs/scalability.md for how to measure it.
      timeout     = "5400s"
      max_retries = 1

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

        env {
          name  = "DEVRADAR_SCAN_MAX_AGE"
          value = var.scan_max_age
        }

        resources {
          limits = {
            cpu = "2000m"
            # Both scanners load a full vuln DB into memory: Grype's stays
            # resident while Trivy downloads + decompresses its own (~1GB+),
            # so peak usage exceeds 2Gi and the job was OOM-killed at that size.
            #
            # Cloud Run's filesystem is memory-backed tmpfs, and Dockerfile.scan
            # fetches both DBs into $HOME at job start, so the DBs are charged
            # against THIS limit — not just the scanners' heap. The DBs grow
            # monotonically upstream, so this ceiling is consumed over time by
            # doing nothing.
            #
            # 4Gi held until 2026-08-15, when the job began failing on SIGBUS
            # (signal 7, not the usual SIGKILL) partway through Trivy's DB
            # download: Trivy mmaps its BoltDB, and an mmap page that tmpfs
            # cannot back raises SIGBUS instead of inviting the OOM killer.
            # 8Gi restores headroom. Watch job-execution failures — the next
            # occurrence means the DBs have outgrown this too, and the fix then
            # is to move the caches off tmpfs (NFS volume; GCS FUSE is a poor
            # fit because BoltDB mmap over FUSE is unreliable) rather than to
            # keep doubling. See docs/scalability.md.
            memory = "8Gi"
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

# ── Transactional email delivery — pure-Go ko image, single bounded task ─────
resource "google_cloud_run_v2_job" "delivery" {
  name                = "${var.prefix}-deliver"
  location            = var.region
  project             = var.project_id
  deletion_protection = false # TODO: set true after initial deploy

  template {
    task_count  = 1
    parallelism = 1

    template {
      service_account = google_service_account.delivery.email
      timeout         = "300s"
      # An immediate platform retry cannot reclaim this failed execution's
      # five-minute leases and would mask the infrastructure error with exit 0.
      # The next scheduled execution recovers them after lease expiry.
      max_retries = 0

      vpc_access {
        network_interfaces {
          network    = local.vpc_id
          subnetwork = local.subnet_id
        }
        egress = "PRIVATE_RANGES_ONLY"
      }

      containers {
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
          name = "SEND_API_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.send_api_key.secret_id
              version = "latest"
            }
          }
        }

        env {
          name = "DEVRADAR_DELIVERY_KEY"
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.delivery_key.secret_id
              version = google_secret_manager_secret_version.delivery_key.version
            }
          }
        }

        env {
          name  = "BASE_URL"
          value = "https://${var.domain}"
        }

        env {
          name  = "EMAIL_FROM"
          value = var.email_from
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
      }

      volumes {
        name = "cloudsql"
        cloud_sql_instance {
          instances = [local.db_connection]
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [template[0].template[0].containers[0].image]
  }

  depends_on = [
    google_project_service.default,
    google_secret_manager_secret_iam_member.delivery_database_url,
    google_secret_manager_secret_iam_member.delivery_delivery_key,
    google_secret_manager_secret_iam_member.delivery_send_api_key,
  ]
}
