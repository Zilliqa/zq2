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

variable "apps" {
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
    condition     = contains(["STANDARD", "SPOT"], var.apps.provisioning_model)
    error_message = "Provisioning model must be one of 'STANDARD' or 'SPOT'."
  }

  # Validation to check that both 'region' and 'zone' are not specified together
  validation {
    condition = alltrue([
      for node in var.apps.nodes : (node.region != null && node.zone == null) || (node.region == null && node.zone != null)
    ])
    error_message = "You need to specify either 'region' or 'zone' for a node."
  }
}

variable "api" {
  description = "(Optional) The configuration of the api nodes"
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
        count  = 3
        region = "asia-southeast1"
      }
    ]
  }

  # Validation for provisioning_model
  validation {
    condition     = contains(["STANDARD", "SPOT"], var.api.provisioning_model)
    error_message = "Provisioning model must be one of 'STANDARD' or 'SPOT'."
  }

  # Validation to check that both 'region' and 'zone' are not specified together
  validation {
    condition = alltrue([
      for node in var.api.nodes : (node.region != null && node.zone == null) || (node.region == null && node.zone != null)
    ])
    error_message = "You need to specify either 'region' or 'zone' for a node."
  }
}

variable "validator" {
  description = "(Optional) The configuration of the validator nodes"
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
        count  = 3
        region = "asia-southeast1"
      }
    ]
  }

  # Validation for provisioning_model
  validation {
    condition     = contains(["STANDARD", "SPOT"], var.validator.provisioning_model)
    error_message = "Provisioning model must be one of 'STANDARD' or 'SPOT'."
  }

  # Validation to check that both 'region' and 'zone' are not specified together
  validation {
    condition = alltrue([
      for node in var.validator.nodes : (node.region != null && node.zone == null) || (node.region == null && node.zone != null)
    ])
    error_message = "You need to specify either 'region' or 'zone' for a node."
  }
}

variable "bootstrap" {
  description = "(Optional) The configuration of the bootstrap nodes"
  type = object({
    disk_size            = optional(number, 256)
    instance_type        = optional(string, "e2-standard-2")
    provisioning_model   = optional(string, "STANDARD")
    generate_external_ip = optional(bool, true)
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
    condition     = contains(["STANDARD", "SPOT"], var.bootstrap.provisioning_model)
    error_message = "Provisioning model must be one of 'STANDARD' or 'SPOT'."
  }

  # Validation to check that both 'region' and 'zone' are not specified together
  validation {
    condition = alltrue([
      for node in var.bootstrap.nodes : (node.region != null && node.zone == null) || (node.region == null && node.zone != null)
    ])
    error_message = "You need to specify either 'region' or 'zone' for a node."
  }
}

variable "checkpoint" {
  description = "(Optional) The configuration of the checkpoint nodes"
  type = object({
    disk_size            = optional(number, 256)
    instance_type        = optional(string, "e2-standard-2")
    provisioning_model   = optional(string, "STANDARD")
    generate_external_ip = optional(bool, false)
    bucket_force_destroy = optional(bool, true)
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
    condition     = contains(["STANDARD", "SPOT"], var.checkpoint.provisioning_model)
    error_message = "Provisioning model must be one of 'STANDARD' or 'SPOT'."
  }

  # Validation to check that both 'region' and 'zone' are not specified together
  validation {
    condition = alltrue([
      for node in var.checkpoint.nodes : (node.region != null && node.zone == null) || (node.region == null && node.zone != null)
    ])
    error_message = "You need to specify either 'region' or 'zone' for a node."
  }
}

variable "node_dns_subdomain" {
  description = "Nodes DNS zone name"
  type        = string
  nullable    = false
}

variable "node_dns_zone_project_id" {
  description = "The id of the Google project that hosts the DNS zone."
  type        = string
  nullable    = false
}

variable "subdomain" {
  description = "The subdomain for the public endpoints"
  type        = string
  nullable    = false
}

variable "chain_name" {
  description = "(Optional) ZQ2 blockchain name"
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

variable "persistence_url" {
  description = "(Optional) ZQ2 Recovery persistence URL"
  type        = string
  nullable    = true
  default     = ""
}

variable "gcp_docker_registry_project_id" {
  description = "(Optional) ZQ2 Artifact Registry project id"
  type        = string
  default     = "prj-p-devops-services-tvwmrf63"
}

variable "persistence_bucket_force_destroy" {
  description = "(Optional) Whether force destroying the persistence bucket deprovisioning the infrastructure."
  type        = bool
  default     = true
  nullable    = false
}
