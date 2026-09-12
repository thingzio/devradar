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

# The Cloud SQL instance and the `thingz` database are owned by shared infra
# (thingzio/infra). DevRadar creates ONLY its own DB user — a separate login (and
# thus a separate connection pool) from DevPulse/DevTrace on the same instance.
# No instance, no database is created here.

data "google_sql_database_instance" "shared" {
  name    = var.db_instance_name
  project = var.project_id
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "google_sql_user" "app" {
  name     = var.db_user
  instance = data.google_sql_database_instance.shared.name
  password = random_password.db_password.result
}
