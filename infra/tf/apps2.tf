################################################################################
# ZQ2 GCP Terraform apps resources
################################################################################

variable "apps" {
  description = "(Optional) The configuration of the apps nodes"
  type = object({
    disk_size          = optional(number, 256)
    instance_type      = optional(string, "e2-standard-2")
    provisioning_model = optional(string, "STANDARD")
    nodes = list(object({
      count  = number
      region = optional(string)
      zone   = optional(string)
    }))
  })
  default = {
    nodes : [
      {
        count  = 1
        region = "asia-southeast1"
      }
    ]
  }

  # Validation for provisioning_model
  validation {
    condition     = contains(["STANDARD", "SPOT"], var.apps.provisioning_model)
    error_message = "Provisioning model must be one of 'STANDARD' or 'SPOT'."
  }

  # Validation to check that both 'region' and 'zone' are not specified together
  validation {
    condition = alltrue([
      for node in var.config.nodes : (node.region != null && node.zone == null) || (node.region == null && node.zone != null)
    ])
    error_message = "You need to specify either 'region' or 'zone' for a node."
  }
}

module "apps2" {
  source = "./modules/node2"

  config = var.apps

  chain_name             = var.chain_name
  role                   = "apps"
  labels                 = {}
  network_tags           = []
  generate_external_ip   = true
  generate_node_key      = true # false
  generate_reward_wallet = true # false
  chain_subdomain        = var.subdomain
  persistence_url        = ""
  genesis_key            = local.genesis_key

  node_dns_subdomain       = var.nodes_dns_zone_name
  node_dns_zone_project_id = var.dns_zone_project_id

  gcp_docker_registry_project_id = var.gcp_docker_registry_project_id
}
