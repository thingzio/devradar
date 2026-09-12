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
