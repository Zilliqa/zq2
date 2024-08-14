variable "name" {
  description = "The instance name"
  type        = string
  nullable    = false
}

variable "service_account_email" {
  description = "The instance service account"
  type        = string
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

variable "vm_num" {
  description = "The number of instances to provision"
  type        = number
  nullable    = false
  default     = 1
}

variable "network_name" {
  description = "The network name"
  type        = string
  nullable    = false
}

variable "subnetwork_name" {
  description = "The subnetwork name"
  type        = string
  nullable    = false
}

variable "subdomain" {
  description = "(Optional) ZQ2 network subdomain"
  type        = string
  default     = ""
}

# variable "secret_keys" {
#   description = "The secret keys to associate with the instances"
#   type        = list(string)
# }

variable "genesis_key" {
  description = "The network genesis key"
  type        = string
  default     = ""
}

variable "node_type" {
  description = "The node type"
  type        = string
  default     = "e2-standard-2"
  nullable    = false
}

variable "node_zones" {
  description = "The instances zone"
  type        = list(string)
  default     = ["europe-west2-a"]
  nullable    = false
}

variable "persistence_url" {
  description = "The persistence url"
  type        = string
  nullable    = true
}

variable "zq_network_name" {
  description = "The ZQ2 network name"
  type        = string
  nullable    = false
}

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

# variable "region" {
#   description = "The region ID to host the network in"
#   type        = string
#   default     = "europe-west2"
# }

variable "role" {
  description = "VM role"
  type        = string
  validation {
    condition     = contains(["bootstrap", "api", "validator", "apps", "checkpoint", "sentry"], var.role)
    error_message = "The role value must be one of:  'bootstrap', 'api', 'validator', 'apps', 'checkpoint', 'sentry'."
  }
}

variable "labels" {
  type        = map(string)
  description = "A single-level map/object with key value pairs of metadata labels to apply to the GCP resources. All keys should use underscores and values should use hyphens. All values must be wrapped in quotes."
  nullable    = true
  default     = {}
}

variable "external_ip" {
  description = "The external IP address. Leave empty for no external IP."
  type        = string
  default     = ""
}

# variable "docker_image" {
#   description = "(Option): ZQ2 validator docker image"
#   type        = string
#   default     = ""
# }

# variable "otterscan_image" {
#   description = "(Optional): Otterscan docker image url (incl. version)"
#   type        = string
#   default     = ""
# }

# variable "spout_image" {
#   description = "(Optional): spout docker image url (incl. version)"
#   type        = string
#   default     = ""
# }
