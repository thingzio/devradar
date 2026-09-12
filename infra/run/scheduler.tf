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

# Triggers the daily scan job via the Cloud Run Admin API. Uses a dedicated SA
# granted run.invoker on the job (see iam.tf).
resource "google_cloud_scheduler_job" "scan" {
  name      = "${var.prefix}-scan-scheduled"
  project   = var.project_id
  region    = var.region
  schedule  = var.scan_schedule
  time_zone = "UTC"

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.scan.name}:run"

    oauth_token {
      service_account_email = google_service_account.scheduler.email
    }
  }

  depends_on = [google_project_service.default]
}

# Executes one bounded outbox pass every 5 minutes. Five durable database
# worker slots bound aggregate concurrency; row leases fence each delivery
# attempt. Invitation delivery is not latency-sensitive, so a 5-min cadence
# cuts Cloud Run Job invocation cost ~5x (43,200 -> 8,640 runs/mo) versus every
# minute, at the cost of up to ~5 min worst-case invite latency.
resource "google_cloud_scheduler_job" "delivery" {
  name      = "${var.prefix}-deliver-scheduled"
  project   = var.project_id
  region    = var.region
  schedule  = "*/5 * * * *"
  time_zone = "UTC"
  paused    = true

  # Terraform creates the job safely paused. The deploy workflow resumes it
  # only after installing all real images; later applies preserve that state.
  lifecycle {
    ignore_changes = [paused]
  }

  http_target {
    http_method = "POST"
    uri         = "https://${var.region}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/${var.project_id}/jobs/${google_cloud_run_v2_job.delivery.name}:run"

    oauth_token {
      service_account_email = google_service_account.scheduler.email
    }
  }

  depends_on = [google_project_service.default]
}
