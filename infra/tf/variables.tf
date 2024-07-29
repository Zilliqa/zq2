################################################################################
# ZQ2 GCP Terraform input variables
################################################################################

variable "project_id" {
  description = "Project ID used to dpeloy the ZQ2 network"
  type        = string
  nullable    = false
}

variable "region" {
  description = "The region ID to host the network in"
  type        = string
  default     = "europe-west2"
}

variable "node_zone" {
  description = "The zone where to provision to"
  type        = string
  nullable    = true
  default     = ""
}

# variable "eth_chain_id" {
#   description = "ZQ2 EVM Chain ID"
#   type        = number
#   nullable    = false
# }

variable "nodes_dns_zone_name" {
  description = "Nodes DNS zone name"
  type        = string
  nullable    = false
}

variable "dns_zone_project_id" {
  description = "The id of the Google project that hosts the DNS zone."
  type        = string
  nullable    = false
}

variable "subdomain" {
  description = "The subdomain for the public endpoints"
  type        = string
  nullable    = false
}

variable "network_name" {
  description = "(Optional) ZQ2 network name"
  type        = string
  nullable    = false
  default     = "zq2-devnet"
}

variable "labels" {
  description = "A single-level map/object with key value pairs of metadata labels to apply to the GCP resources. All keys should use underscores and values should use hyphens. All values must be wrapped in quotes."
  type        = map(string)
  nullable    = true
  default     = {}
}

variable "vpc_main_subnet_name" {
  description = "(Optional) ZQ2 VPC subnet name"
  type        = string
  nullable    = false
}

variable "genesis_key" {
  description = "(Optional) Genesis private key"
  type        = string
  nullable    = false
}

variable "bootstrap_key" {
  description = "(Optional) Boostrap node private key"
  type        = string
  nullable    = false
}

variable "apps_node_count" {
  description = "(Optional) ZQ2 Node apps count"
  type        = number
  nullable    = false
  default     = 1
}

variable "api_node_private_keys" {
  description = "(Optional) API node private key"
  type        = list(string)
  nullable    = false
}

variable "validator_node_private_keys" {
  description = "(Optional) ZQ2 Nodes secret keys"
  type        = list(string)
  nullable    = false
}

variable "persistence_url" {
  description = "(Optional) ZQ2 Recovery persistence URL"
  type        = string
  nullable    = true
  default     = ""
}

# variable "docker_image" {
#   description = "ZQ2 Docker image URL"
#   type        = string
#   default     = ""
# }

# variable "otterscan_image" {
#   description = "Otterscan Docker image URL"
#   type        = string
#   default     = ""
# }

# variable "spout_image" {
#   description = "Spout Docker image URL"
#   type        = string
#   default     = ""
# }

variable "gcp_docker_registry_project_id" {
  description = "(Optional) ZQ2 Artifact Registry project id"
  type        = string
  default     = "prj-p-devops-services-tvwmrf63"
}

variable "distributed_validators" {
  description = "(Optional) regional validators deployment. Useful for distributed load tests."
  type = list(object({
    region          = string
    vm_num          = number
    vpc_subnet_name = string
    vm_type         = optional(string)
    node_keys       = list(string)
    vm_zone         = optional(string)
  }))
  default = []
  validation {
    condition     = alltrue([for v in var.distributed_validators : (length(v.node_keys) == v.vm_num)])
    error_message = "ERROR: num of vms and number of keys mismatch"
  }
}

variable "apps_node_type" {
  description = "(Optional) The size of the nodes."
  type        = string
  default     = "e2-standard-2"
  nullable    = false
}
