################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

locals {
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
        resource_name   = format("%s-%s-%s-%s", var.chain_name, lookup(local.labels, "private-api", var.role), var.region_mappings[(node.region != null ? node.region : ([for region in data.google_compute_zones.available : region if contains(region.names, node.zone)][0].region))], n)
        resource_id     = format("%s-%s-%s-%s", var.chain_name, var.role, var.region_mappings[(node.region != null ? node.region : ([for region in data.google_compute_zones.available : region if contains(region.names, node.zone)][0].region))], n)
        image           = lookup(try(var.config.os_images_override, {}), format("%s-%s-%s-%s", var.chain_name, lookup(local.labels, "private-api", var.role), var.region_mappings[(node.region != null ? node.region : ([for region in data.google_compute_zones.available : region if contains(region.names, node.zone)][0].region))], n), "ubuntu-os-cloud/ubuntu-2404-lts-amd64")
        instance_type   = lookup(try(var.config.instance_type_override, {}), format("%s-%s-%s-%s", var.chain_name, lookup(local.labels, "private-api", var.role), var.region_mappings[(node.region != null ? node.region : ([for region in data.google_compute_zones.available : region if contains(region.names, node.zone)][0].region))], n), var.config.instance_type)
        boot_disk_size  = lookup(try(var.config.boot_disk_size_override, {}), format("%s-%s-%s-%s", var.chain_name, lookup(local.labels, "private-api", var.role), var.region_mappings[(node.region != null ? node.region : ([for region in data.google_compute_zones.available : region if contains(region.names, node.zone)][0].region))], n), var.config.boot_disk_size)
        data_disk_size  = lookup(try(var.config.data_disk_size_override, {}), format("%s-%s-%s-%s", var.chain_name, lookup(local.labels, "private-api", var.role), var.region_mappings[(node.region != null ? node.region : ([for region in data.google_compute_zones.available : region if contains(region.names, node.zone)][0].region))], n), var.config.data_disk_size)
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
