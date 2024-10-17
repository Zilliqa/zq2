################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

locals {
  network_tier = "PREMIUM"
  labels = merge(
    { "zq2-network" = var.zq2_chain_name },
    { "role" = var.role },
    { "node-name" = var.name },
    var.labels
  )
  tags = flatten(concat(var.network_tags, [var.zq2_chain_name, format("%s-%s", var.zq2_chain_name, var.role)]))
}
