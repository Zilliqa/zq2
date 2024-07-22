#########################
# Terraform providers' version
#########################

terraform {
  required_version = ">= 1.5.7"
  required_providers {

    google = {
      source  = "hashicorp/google"
      version = ">= 4.50, < 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 4.50, < 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 2.1"
    }
  }
}
