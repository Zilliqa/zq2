################################################################################
# ZQ2 GCP Terraform datasource
################################################################################

data "google_compute_subnetwork" "default" {
  project = var.project_id
  region  = var.region
  name    = var.vpc_main_subnet_name
}
