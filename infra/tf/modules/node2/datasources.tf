################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

data "google_project" "current" {}

# Data to retrieve all zones in the region if only a region is specified
data "google_compute_zones" "available" {
  count  = length(var.config.nodes)
  region = lookup(var.config.nodes[count.index], "region", null)
}
