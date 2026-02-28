terraform {
  backend "gcs" {
    # bucket and prefix are passed via -backend-config flags or GOOGLE_BACKEND_CONFIG.
    # Example: terraform init -backend-config="bucket=my-tf-state"
    prefix = "oast-mcp/state"
  }

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  required_version = ">= 1.5"
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}
