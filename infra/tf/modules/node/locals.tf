################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

locals {
  node_dns_zone_name = replace(var.node_dns_subdomain, ".", "-")
  resource_name      = format("%s-%s-%s", var.chain_name, local.role_short_name, random_id.name_suffix.hex)
  role_short_name    = var.node_role_mappings[var.role]

  regions = flatten([
    for instance in local.instances : instance.region
  ])

  instances = flatten([
    for idx, node in var.config.nodes : [
      for n in range(node.count) : {
        region_index    = idx
        in_region_index = n
        count           = node.count
        region          = node.region != null ? node.region : ([for region in data.google_compute_zones.available : region if contains(region.names, node.zone)][0].region)
        zone            = node.zone != null ? node.zone : ([for region in data.google_compute_zones.available : region if region.region == node.region][0].names[n % length([for region in data.google_compute_zones.available : region if region.region == node.region][0].names)])
        resource_name   = format("%s-%s-%s-%s-%s", var.chain_name, var.role, var.region_mappings[(node.region != null ? node.region : ([for region in data.google_compute_zones.available : region if contains(region.names, node.zone)][0].region))], n, random_id.name_suffix.hex)
        resource_id     = format("%s-%s-%s-%s", var.chain_name, var.role, var.region_mappings[(node.region != null ? node.region : ([for region in data.google_compute_zones.available : region if contains(region.names, node.zone)][0].region))], n)
      }
    ]
  ])

  instances_map = {
    for instance in local.instances : instance.resource_id => instance
  }

  network_tags = flatten(concat(var.network_tags, [var.chain_name, format("%s-%s", var.chain_name, var.role)]))
  labels = merge(
    { "zq2-network" = var.chain_name },
    { "role" = var.role },
    var.labels
  )
}
