################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

locals {
  node_dns_zone_name = replace(var.node_dns_subdomain, ".", "-")
  resource_name      = format("%s-%s-%s", var.chain_name, local.role_short_name, random_id.name_suffix.hex)
  role_short_name = var.node_role_mappings[var.role]

  instances = flatten([
    for idx, node in var.config.nodes : [
      for n in range(node.count) : {
        region_index = idx
        in_region_index = n
        count = node.count
        region = node.region != null ? node.region : ([for region in data.google_compute_zones.available : region if contains(region.names, node.zone)][0].region)
        zone = node.zone != null ? node.zone : ([for region in data.google_compute_zones.available : region if region.region == node.region][0].names[n])
      }
    ]
  ])

  network_tags = flatten(concat(var.network_tags, [var.chain_name, format("%s-%s", var.chain_name, var.role)]))
    labels = merge(
    { "zq2-network" = var.chain_name },
    { "role" = var.role },
    { "node-name" = "${local.resource_name}" },
    var.labels
  )
}


# lookup(
#     var.config.nodes[local.instances[count.index].node_index], "zone",
#     data.google_compute_zones.available[local.instances[count.index].node_index].zones[count.index % length(data.google_compute_zones.available[local.instances[count.index].node_index].zones)]
#   )

  # total unique zones
