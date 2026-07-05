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

  backend "gcs" {
    bucket = "thingzio-infra-state"
    prefix = "devradar"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
