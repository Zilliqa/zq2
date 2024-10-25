variable "node_role_mappings" {
  description = "(Optional) The node role short names"
  type        = map(string)
  default = {
    apps       = "app",
    api        = "api",
    bootstrap  = "boo",
    validator  = "val",
    checkpoint = "che",
    sentry     = "sen",
  }
}

variable "region_mappings" {
  description = "(Optional) The regions short names"
  type        = map(string)
  default = {
    "europe-west1"    = "ewe1"
    "europe-west2"    = "ewe2"
    "asia-southeast1" = "ase1"
    "us-west1"        = "usw1"
  }
}

variable "config" {
  description = "(Optional) The configuration of the apps nodes"
  type = object({
    disk_size            = optional(number, 256)
    instance_type        = optional(string, "e2-standard-2")
    provisioning_model   = optional(string, "STANDARD")
    generate_external_ip = optional(bool, false)
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
    condition     = contains(["STANDARD", "SPOT"], var.config.provisioning_model)
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

variable "chain_name" {
  description = "The blockchain name"
  type        = string
  nullable    = false
}

variable "role" {
  description = "VM role"
  type        = string
  validation {
    condition     = contains(["bootstrap", "api", "validator", "apps", "checkpoint", "sentry"], var.role)
    error_message = "The role value must be one of:  'bootstrap', 'api', 'validator', 'apps', 'checkpoint', 'sentry'."
  }
}

variable "metadata" {
  description = "(Optional) The instance metadata"
  type        = map(string)
  default     = {}
}

variable "labels" {
  type        = map(string)
  description = "A single-level map/object with key value pairs of metadata labels to apply to the GCP resources. All keys should use underscores and values should use hyphens. All values must be wrapped in quotes."
  nullable    = true
  default     = {}
}

variable "network_tags" {
  description = "The network tags"
  type        = list(string)
  default     = []
  nullable    = false
}

variable "generate_node_key" {
  description = "Enable private key generation"
  type        = bool
  nullable    = false
  default     = true
}

variable "generate_reward_wallet" {
  description = "Enable reward wallet generation"
  type        = bool
  nullable    = false
  default     = false
}

variable "node_dns_subdomain" {
  description = "Nodes DNS zone name (ie. zq2.dev)"
  type        = string
  nullable    = false
}

variable "node_dns_zone_project_id" {
  description = "The id of the Google project that hosts the DNS zone."
  type        = string
  nullable    = false
}

variable "service_account_iam" {
  description = "(Optional) Roles to associate to the instances service account"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for permission in var.service_account_iam : length(split("=>", permission)) == 2
    ])
    error_message = "You need to specify the permissions in the form role=>project_id (ie. roles/monitoring.metricWriter=>prj-d-zq2-devnet-c83bkpsd)"
  }
}
