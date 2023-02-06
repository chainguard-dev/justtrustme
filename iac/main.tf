terraform {
  required_providers {
    ko = {
      source = "ko-build/ko"
    }
    google = {
      source = "hashicorp/google"
    }
  }
  backend "gcs" {
    bucket = "artifacts.just-trust-me.appspot.com"
    prefix = "/iac"
  }
}

locals {
  project_id = "just-trust-me"
}

provider "google" {
  project = local.project_id
}

data "google_project" "project" {}

// Create a non-default service account for the service to run as.
resource "google_service_account" "issuer" {
  project    = local.project_id
  account_id = "issuer"
}

// Build the issuer into an image we can run on Cloud Run.
resource "ko_image" "image" {
  repo        = "gcr.io/${local.project_id}/issuer"
  base_image  = "cgr.dev/chainguard/static:latest-glibc"
  importpath  = "github.com/chainguard-dev/justtrustme"
  working_dir = "${path.module}/.."
}

// Spin up a Cloud Run service to host our issuer.
resource "google_cloud_run_service" "issuer" {
  project  = local.project_id
  name     = "just-trust-me"
  location = "us-west1"

  template {
    metadata {
      annotations = {
        "autoscaling.knative.dev/minScale" : "1"
        "autoscaling.knative.dev/maxScale" : "1"
      }
    }
    spec {
      service_account_name = google_service_account.issuer.email
      containers {
        image = ko_image.image.image_ref
      }
    }
  }
}

data "google_iam_policy" "noauth" {
  binding {
    role = "roles/run.invoker"
    members = [
      "allUsers",
    ]
  }
}

resource "google_cloud_run_service_iam_policy" "noauths" {
  project  = local.project_id
  location = google_cloud_run_service.issuer.location
  service  = google_cloud_run_service.issuer.name

  policy_data = data.google_iam_policy.noauth.policy_data
}
