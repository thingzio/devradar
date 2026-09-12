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
