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

# Secrets DevRadar owns. Registry credentials are intentionally absent — DevRadar
# never pulls images. Values use generated, out-of-band, or tfvars-backed sources
# as documented per secret below.

# Session-bound API token flashes use an application-level encryption key. This
# value remains stable in Terraform state until an operator explicitly replaces
# random_id.token_flash_key.
resource "random_id" "token_flash_key" {
  byte_length = 32
}

resource "google_secret_manager_secret" "token_flash_key" {
  secret_id = "${var.prefix}-token-flash-key"
  project   = var.project_id
  replication {
    auto {}
  }
  depends_on = [google_project_service.default]
}

resource "google_secret_manager_secret_version" "token_flash_key" {
  secret      = google_secret_manager_secret.token_flash_key.id
  secret_data = random_id.token_flash_key.b64_std

  lifecycle {
    create_before_destroy = true
  }
}

# Pending invitation payloads use a separate durable application-level key so
# delivery access never grants access to session token flashes.
resource "random_id" "delivery_key" {
  byte_length = 32
}

resource "google_secret_manager_secret" "delivery_key" {
  secret_id = "${var.prefix}-delivery-key"
  project   = var.project_id
  replication {
    auto {}
  }
  depends_on = [google_project_service.default]
}

resource "google_secret_manager_secret_version" "delivery_key" {
  secret      = google_secret_manager_secret.delivery_key.id
  secret_data = random_id.delivery_key.b64_std

  lifecycle {
    create_before_destroy = true
  }
}

resource "google_secret_manager_secret" "database_url" {
  secret_id = "${var.prefix}-database-url"
  project   = var.project_id
  replication {
    auto {}
  }
  depends_on = [google_project_service.default]
}

resource "google_secret_manager_secret_version" "database_url" {
  secret = google_secret_manager_secret.database_url.id
  # Cloud SQL unix-socket DSN via the mounted /cloudsql volume.
  secret_data = "host=/cloudsql/${local.db_connection} dbname=${var.db_name} user=${google_sql_user.app.name} password=${random_password.db_password.result} sslmode=disable"
}

# Resend API key — magic-link sign-in (and, later, alerts).
resource "google_secret_manager_secret" "send_api_key" {
  secret_id = "${var.prefix}-send-api-key"
  project   = var.project_id
  replication {
    auto {}
  }
  depends_on = [google_project_service.default]
}

# Seed a placeholder version so the serve service (which references this secret's
# `latest`) can deploy before the real key is set. Replace the value out-of-band
# (`gcloud secrets versions add`); ignore_changes keeps that real value from
# being reverted on the next `terraform apply`. With the placeholder, magic-link
# email sending is a no-op (links are logged) until the real key is added.
resource "google_secret_manager_secret_version" "send_api_key_placeholder" {
  secret      = google_secret_manager_secret.send_api_key.id
  secret_data = "placeholder-set-real-value-out-of-band"

  lifecycle {
    ignore_changes = [secret_data]
  }
}

# Anthropic API key — optional (admin /metrics AI health summary; OpenVEX
# stubbing / future narratives).
resource "google_secret_manager_secret" "anthropic_api_key" {
  secret_id = "${var.prefix}-anthropic-api-key"
  project   = var.project_id
  replication {
    auto {}
  }
  depends_on = [google_project_service.default]
}

# The value comes from var.anthropic_api_key, set in the gitignored
# terraform.tfvars (never committed) — same pattern as the OAuth client secret.
# When the var is empty a placeholder is written so serve (which references
# `latest`) can still deploy; the claude client treats the placeholder as unset
# (New() → nil), so the AI health summary stays off until a real value is set.
# No ignore_changes: tfvars is the source of truth, so updating it and
# re-applying rotates the key.
resource "google_secret_manager_secret_version" "anthropic_api_key" {
  secret      = google_secret_manager_secret.anthropic_api_key.id
  secret_data = var.anthropic_api_key != "" ? var.anthropic_api_key : "placeholder-set-real-value-out-of-band"
}

# GitHub OAuth App client secret — UI sign-in via GitHub. The client *ID* is a
# public identifier passed as a plain env var (var.github_oauth_client_id); only
# this secret is sensitive.
resource "google_secret_manager_secret" "oauth_client_secret" {
  secret_id = "${var.prefix}-oauth-client-secret"
  project   = var.project_id
  replication {
    auto {}
  }
  depends_on = [google_project_service.default]
}

# The secret value is supplied from var.github_oauth_client_secret, set in the
# gitignored terraform.tfvars (never committed) — same pattern DevTrace uses for
# github_token. When the var is empty a placeholder is written so serve (which
# references `latest`) can still deploy; the config layer treats the placeholder
# as unset (GitHubOAuthConfigured() → false), so the UI stays email-only until a
# real value is provided. No ignore_changes here: tfvars is the source of truth,
# so updating the tfvars value and re-applying rotates the secret.
resource "google_secret_manager_secret_version" "oauth_client_secret" {
  secret      = google_secret_manager_secret.oauth_client_secret.id
  secret_data = var.github_oauth_client_secret != "" ? var.github_oauth_client_secret : "placeholder-set-real-value-out-of-band"
}

# --- Grant the run SA read access to each secret ---

resource "google_secret_manager_secret_iam_member" "run_database_url" {
  secret_id = google_secret_manager_secret.database_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}

resource "google_secret_manager_secret_iam_member" "run_token_flash_key" {
  secret_id = google_secret_manager_secret.token_flash_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}

resource "google_secret_manager_secret_iam_member" "run_delivery_key" {
  secret_id = google_secret_manager_secret.delivery_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}

resource "google_secret_manager_secret_iam_member" "run_send_api_key" {
  secret_id = google_secret_manager_secret.send_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}

resource "google_secret_manager_secret_iam_member" "run_anthropic" {
  secret_id = google_secret_manager_secret.anthropic_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}

resource "google_secret_manager_secret_iam_member" "run_oauth_client_secret" {
  secret_id = google_secret_manager_secret.oauth_client_secret.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.run.email}"
}

# The delivery runtime can read only the three secrets needed to lease,
# decrypt, and send outbox rows.
resource "google_secret_manager_secret_iam_member" "delivery_database_url" {
  secret_id = google_secret_manager_secret.database_url.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.delivery.email}"
}

resource "google_secret_manager_secret_iam_member" "delivery_send_api_key" {
  secret_id = google_secret_manager_secret.send_api_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.delivery.email}"
}

resource "google_secret_manager_secret_iam_member" "delivery_delivery_key" {
  secret_id = google_secret_manager_secret.delivery_key.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.delivery.email}"
}
