################################################################################
# ZQ2 GCP Terraform providers version
################################################################################

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.73.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.1"
    }
  }
}