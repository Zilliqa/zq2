################################################################################
# ZQ2 GCP Terraform datasources variables
################################################################################

data "google_project" "current" {}

data "google_compute_zones" "available" {
  count  = length(var.config.nodes)
  region = lookup(var.config.nodes[count.index], "region", null)
}

data "google_compute_subnetworks" "default" {
  for_each = toset(local.regions)
  project  = data.google_project.current.project_id
  filter   = "privateIpGoogleAccess eq true"
  region   = each.value
}
