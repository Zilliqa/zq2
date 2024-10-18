################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

# Data to retrieve all zones in the region if only a region is specified
data "google_compute_zones" "available" {
  count  = length(var.apps.nodes)
  region = lookup(var.apps.nodes[count.index], "region", null)
}
