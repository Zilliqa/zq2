variable "project_id" {
  description = "Project ID used to dpeloy the ZQ2 network"
  type        = string
  nullable    = false
}

variable "name" {
  description = "The instance name"
  type        = string
  nullable    = false
}

variable "provisioning_model" {
  description = "The provisioning model for the instance. Must be either 'STANDARD' or 'SPOT'."
  type        = string

  validation {
    condition     = contains(["STANDARD", "SPOT"], var.provisioning_model)
    error_message = "The provisioning model must be either 'STANDARD' or 'SPOT'."
  }

  default = "STANDARD"
}

variable "network_name" {
  description = "The GCP network name"
  type        = string
  nullable    = false
}

variable "subnetwork_name" {
  description = "The GCP subnetwork name"
  type        = string
  nullable    = false
}

variable "instance_type" {
  description = "The GCP instance type"
  type        = string
  default     = "e2-standard-2"
  nullable    = false
}

variable "region" {
  description = "The instance region"
  type        = string
  nullable    = false
}

variable "zone" {
  description = "The instance zone"
  type        = string
  nullable    = false
}

variable "labels" {
  type        = map(string)
  description = "A single-level map/object with key value pairs of metadata labels to apply to the GCP resources. All keys should use underscores and values should use hyphens. All values must be wrapped in quotes."
  default     = {}
  nullable    = true
}

variable "network_tags" {
  description = "The network tags"
  type        = list(string)
  default     = []
  nullable    = true
}

variable "disk_size" {
  description = "The instance disk size"
  type        = number
  default     = 256
  nullable    = false
}

variable "zq2_chain_name" {
  description = "The ZQ2 network name"
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

variable "docker_registry_project_id" {
  description = "(Optional) ZQ2 Artifact Registry project ID"
  type        = string
  default     = "prj-p-devops-services-tvwmrf63"
}

variable "persistence_url" {
  description = "The persistence url"
  type        = string
  nullable    = true
}

variable "zq2_chain_subdomain" {
  description = "(Optional) ZQ2 chain subdomain (ie. zq2-prototestnet.zilliqa.com)"
  type        = string
  default     = ""
}

variable "genesis_key" {
  description = "The blockchain genesis key"
  type        = string
  default     = ""
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
