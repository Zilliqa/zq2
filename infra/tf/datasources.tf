################################################################################
# ZQ2 GCP Terraform datasource
################################################################################
data "google_compute_subnetwork" "default" {
  project = var.project_id
  region  = var.region
  name    = var.vpc_main_subnet_name != "" ? var.vpc_main_subnet_name : google_compute_subnetwork.subnet.0.name
}