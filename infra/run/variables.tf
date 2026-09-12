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

variable "project_id" {
  description = "GCP project ID for the SaaS deployment"
  type        = string
}

variable "region" {
  description = "GCP region for Cloud Run"
  type        = string
  default     = "us-west1"
}

variable "prefix" {
  description = "Unique deployment identifier (used to name service resources)"
  type        = string
  default     = "devradar-saas"
}

variable "domain" {
  description = "Public domain for the service"
  type        = string
}

variable "git_repo" {
  description = "GitHub repository for Workload Identity Federation"
  type        = string
}

variable "bootstrap_image" {
  description = <<-EOT
    Placeholder image used ONLY to create the Cloud Run resources on the first
    apply, before CI has pushed the real images. This is an immutable digest of
    Google's public sample server. Delivery scheduling remains paused while it
    is installed. After creation, CI sets the real images; Terraform ignores
    image changes thereafter (see cloudrun.tf lifecycle blocks).
  EOT
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello@sha256:3beb8d6dd8bac1c597d10f3ddf59f5f684d6054ab589c4334c0486dad07a3f97"
}

variable "notification_email" {
  description = "Email address for infra alert notifications"
  type        = string
}

variable "email_from" {
  description = "From address for outbound transactional email (magic-link). Must sit under a Resend-verified domain — the root thingz.io is verified; subdomains are not."
  type        = string
}

variable "scan_schedule" {
  description = "Cron schedule (UTC) for the scan job. Runs frequently; each SBOM is scanned at most as often as DEVRADAR_SCAN_MAX_AGE allows, so a frequent schedule bounds submission-to-result latency without over-scanning."
  type        = string
  default     = "*/15 * * * *"
}

variable "scan_max_age" {
  description = "Staleness window (Go duration) for scan-job work selection: an SBOM is scanned only if never scanned or last scanned longer ago than this. Overrides the code default (12h) to bound per-SBOM scan compute as the fleet grows."
  type        = string
  default     = "24h"
}

variable "github_oauth_client_id" {
  description = "GitHub OAuth App client ID for UI sign-in (public identifier, not a secret — injected as a plain env var). The matching client secret is stored in Secret Manager (devradar-saas-oauth-client-secret). Has no default: set it explicitly, to an empty string to disable GitHub sign-in (falls back to email-only magic links)."
  type        = string
}

variable "github_oauth_client_secret" {
  description = "GitHub OAuth App client secret for UI sign-in. Set in the gitignored terraform.tfvars (never committed); flows into Secret Manager. Has no default on purpose: an absent tfvars would otherwise read as empty and overwrite the live secret with a placeholder. Set it explicitly, to an empty string to keep the placeholder and leave GitHub sign-in disabled."
  type        = string
  sensitive   = true
}

variable "admin_users" {
  description = "Comma-separated verified emails allowed into the /admin operator console (DEVRADAR_ADMIN_USERS). Case-insensitive. Not a secret — it's an allowlist of operator emails, injected as a plain env var. Has no default: set it explicitly, to an empty string to leave the console fully hidden (every /admin route returns 404)."
  type        = string
}

variable "account_sharing_enabled" {
  description = "Enables account invitations and membership management. Keep false until production migrations and sharing workflows are validated."
  type        = bool
  default     = false
}

variable "anthropic_api_key" {
  description = "Anthropic API key for the admin /metrics AI health summary (and later narratives). Set in the gitignored terraform.tfvars (never committed); flows into Secret Manager. Has no default on purpose: an absent tfvars would otherwise read as empty and overwrite the live secret with a placeholder. Set it explicitly, to an empty string to keep the placeholder — the summary stays off and raw metrics still render."
  type        = string
  sensitive   = true
}

# --- Shared infrastructure (owned by thingzio/infra; referenced, not created) ---

variable "vpc_id" {
  description = "Shared VPC network ID"
  type        = string
}

variable "subnet_id" {
  description = "Shared VPC subnet ID"
  type        = string
}

variable "db_instance_name" {
  description = "Shared Cloud SQL instance name (referenced, never created here)"
  type        = string
}

variable "db_connection_name" {
  description = "Shared Cloud SQL connection string (project:region:instance)"
  type        = string
}

variable "db_name" {
  description = "Existing database within the shared Cloud SQL instance"
  type        = string
}

variable "db_user" {
  description = "DevRadar's own DB user in the shared instance (separate pool from siblings)"
  type        = string
  default     = "devradar"
}

variable "remote_image_repository" {
  description = <<-EOT
    Artifact Registry remote repository that fronts ghcr.io. Images are built
    and signed on GitHub and published to GHCR; Cloud Run will only pull from
    Artifact Registry, so it pulls through this repository. It is a
    pull-through cache, not a copy, so the digest is unchanged on the far side.

    Shared across the thingzio services and created outside this module, so it
    is named rather than managed here.
  EOT
  type        = string
  default     = "gh"
}
