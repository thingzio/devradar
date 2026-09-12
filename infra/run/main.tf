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

locals {
  # Shared infra references (from variables, not remote state — matches siblings).
  vpc_id        = var.vpc_id
  subnet_id     = var.subnet_id
  db_connection = var.db_connection_name


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
