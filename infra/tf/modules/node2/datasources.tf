################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

data "google_project" "current" {}

# Data to retrieve all zones in the region if only a region is specified
data "google_compute_zones" "available" {
  count  = length(var.config.nodes)
  region = lookup(var.config.nodes[count.index], "region", null)
}

# data "google_compute_subnetwork" "default" {
#   project = data.google_project.current.project_id
#   # region  = var.region
#   # name    = var.vpc_main_subnet_name
# }

data "google_compute_subnetworks" "default" {
  for_each = toset(local.regions)
  project  = data.google_project.current.project_id
  filter   = "privateIpGoogleAccess eq true"
  region   = each.value
}
