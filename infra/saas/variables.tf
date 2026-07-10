variable "project_id" {
  description = "GCP project ID for the SaaS deployment"
  type        = string
  default     = "thingzio"
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
  default     = "devradar.thingz.io"
}

variable "git_repo" {
  description = "GitHub repository for Workload Identity Federation"
  type        = string
  default     = "thingzio/devradar"
}

variable "bootstrap_image" {
  description = <<-EOT
    Placeholder image used ONLY to create the Cloud Run resources on the first
    apply, before CI has pushed the real images. A public Google sample image
    that serves HTTP on 8080. After creation, CI (gcloud run deploy) sets the
    real image; Terraform ignores image changes thereafter (see cloudrun.tf
    lifecycle blocks), so this value is never re-applied.
  EOT
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "notification_email" {
  description = "Email address for infra alert notifications"
  type        = string
  default     = "devradar@thingz.io"
}

variable "email_from" {
  description = "From address for outbound transactional email (magic-link). Must sit under a Resend-verified domain — the root thingz.io is verified; subdomains are not."
  type        = string
  default     = "DevRadar <no-reply@thingz.io>"
}

variable "scan_schedule" {
  description = "Cron schedule (UTC) for the scan job. Runs frequently; each SBOM is scanned at most as often as DEVRADAR_SCAN_MAX_AGE allows (default 12h), so a frequent schedule bounds submission-to-result latency without over-scanning."
  type        = string
  default     = "*/15 * * * *"
}

variable "github_oauth_client_id" {
  description = "GitHub OAuth App client ID for UI sign-in (public identifier, not a secret — injected as a plain env var). The matching client secret is stored in Secret Manager (devradar-saas-oauth-client-secret). Leave empty to disable GitHub sign-in (falls back to email-only magic links)."
  type        = string
  default     = ""
}

variable "github_oauth_client_secret" {
  description = "GitHub OAuth App client secret for UI sign-in. Set in the gitignored terraform.tfvars (never committed); flows into Secret Manager. Leave empty to keep the placeholder (GitHub sign-in stays disabled)."
  type        = string
  default     = ""
  sensitive   = true
}

variable "admin_users" {
  description = "Comma-separated verified emails allowed into the /admin operator console (DEVRADAR_ADMIN_USERS). Case-insensitive. Not a secret — it's an allowlist of operator emails, injected as a plain env var. Empty leaves the console fully hidden (every /admin route returns 404)."
  type        = string
  default     = ""
}

variable "anthropic_api_key" {
  description = "Anthropic API key for the admin /metrics AI health summary (and later narratives). Set in the gitignored terraform.tfvars (never committed); flows into Secret Manager. Leave empty to keep the placeholder (the summary stays off; raw metrics still render)."
  type        = string
  default     = ""
  sensitive   = true
}

# --- Shared infrastructure (owned by thingzio/infra; referenced, not created) ---

variable "vpc_id" {
  description = "Shared VPC network ID"
  type        = string
  default     = "projects/thingzio/global/networks/thingzio-vpc"
}

variable "subnet_id" {
  description = "Shared VPC subnet ID"
  type        = string
  default     = "projects/thingzio/regions/us-west1/subnetworks/thingzio-subnet"
}

variable "db_instance_name" {
  description = "Shared Cloud SQL instance name (referenced, never created here)"
  type        = string
  default     = "thingzio-pg"
}

variable "db_connection_name" {
  description = "Shared Cloud SQL connection string (project:region:instance)"
  type        = string
  default     = "thingzio:us-west1:thingzio-pg"
}

variable "db_name" {
  description = "Existing database within the shared Cloud SQL instance"
  type        = string
  default     = "thingz"
}

variable "db_user" {
  description = "DevRadar's own DB user in the shared instance (separate pool from siblings)"
  type        = string
  default     = "devradar"
}
