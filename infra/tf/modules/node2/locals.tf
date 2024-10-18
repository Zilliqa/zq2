################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

locals {
  node_dns_zone_name = replace(var.node_dns_subdomain, ".", "-")
  resource_name      = format("%s-%s-%s", var.chain_name, var.node_role_mappings[var.role], random_id.name_suffix.hex)
}
