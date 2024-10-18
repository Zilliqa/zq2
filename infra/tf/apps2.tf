################################################################################
# ZQ2 GCP Terraform apps resources
################################################################################

variable "apps" {
  description = "(Optional) The configuration of the apps nodes"
  type = object({
    disk_size           = optional(number, 256)
    instance_type       = optional(string, "e2-standard-2")
    provisioning_model  = optional(string, "STANDARD")
    nodes               = list(object({
      count  = optional(number, 1)
      region = optional(string)
      zone   = optional(string)
    }))
  })
  default     = { nodes: {}}
}

# Validation for provisioning_model
locals {
  apps_nodes = [
    for node in var.apps["nodes"] : {
      count  = node.count
      region = lookup(node, "region", null)
      zone   = lookup(node, "zone", null)
    }
  ]

  # Raise an error if both region and zone are specified
  validation_region_zone = [
    for node in local.apps_nodes : {
      error = node.region != null && node.zone != null ? "Cannot specify both region and zone" : null
    }
  ]

  # Validate provisioning_model only allows STANDARD or SPOT
  validation_provisioning_model = contains(["STANDARD", "SPOT"], var.apps["provisioning_model"]) ? null : "Provisioning model must be STANDARD or SPOT"
}

resource "google_service_account" "apps2" {
  account_id = substr("${var.chain_name}-apps2", 0, 28)
}

module "apps2" {
  source = "./modules/node2"
  vm_num = var.apps_node_count

  role                  = "apps"
  name                  = "${var.chain_name}-apps2"
  service_account_email = google_service_account.apps2.email
  dns_zone_project_id   = var.dns_zone_project_id
  nodes_dns_zone_name   = var.nodes_dns_zone_name
  network_name          = local.network_name
  subnetwork_name       = data.google_compute_subnetwork.default.name
  node_zones            = local.default_zones
  subdomain             = var.subdomain
  generate_node_key     = false
  persistence_url       = ""
  genesis_key           = local.genesis_key
  node_type             = var.apps_node_type
  provisioning_model    = var.provisioning_model

  zq_network_name = var.chain_name
}

resource "google_compute_instance_group" "apps2" {
  for_each = toset(local.default_zones)

  name      = "${var.chain_name}-apps2-${each.key}"
  zone      = each.key
  instances = [for instance in module.apps.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "otterscan"
    port = "80"
  }

  named_port {
    name = "spout"
    port = "8080"
  }
}
