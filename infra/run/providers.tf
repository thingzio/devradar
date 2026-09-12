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

terraform {
  required_version = ">= 1.13"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.9"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Partial backend configuration. The bucket is deployment-specific, so it is
  # supplied at init time rather than committed:
  #
  #   terraform init -backend-config=backend.hcl
  #
  # `make tf-init` does that for you. See backend.hcl.example; backend.hcl is
  # gitignored. State is keyed by the `prefix` set there, not by this directory.
  backend "gcs" {}
}

provider "google" {
  project = var.project_id
  region  = var.region
}
