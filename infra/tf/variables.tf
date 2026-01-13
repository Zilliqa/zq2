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
    boot_disk_size             = optional(number, 100)
    data_disk_size             = optional(number, 0)
    instance_type              = optional(string, "e2-standard-2")
    provisioning_model         = optional(string, "STANDARD")
    generate_external_ip       = optional(bool, false)
    detach_load_balancer       = optional(bool, false)
    enable_faucet              = optional(bool, true)
    faucet_max_hourly_requests = optional(number, 1000000)
    alternative_ssl_domains = optional(object({
      otterscan = optional(list(string), [])
      faucet    = optional(list(string), [])
      stats     = optional(list(string), [])
    }), {})
    nodes = optional(list(object({
      count  = number
      region = optional(string)
      zone   = optional(string)
    })), [])
    os_images_override      = optional(map(string), {})
    instance_type_override  = optional(map(string), {})
    disk_snapshot_override  = optional(map(string), {})
    boot_disk_size_override = optional(map(number), {})
    data_disk_size_override = optional(map(number), {})
  })
  default = {}

  # Validation for provisioning_model
  validation {
    condition     = var.apps.faucet_max_hourly_requests >= 1 && var.apps.faucet_max_hourly_requests <= 1000000
    error_message = "Rate limit must be a positive integer between 1 and 1,000,000."
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
    boot_disk_size       = optional(number, 100)
    data_disk_size       = optional(number, 100)
    instance_type        = optional(string, "e2-standard-2")
    provisioning_model   = optional(string, "STANDARD")
    generate_external_ip = optional(bool, false)
    detach_load_balancer = optional(bool, false)
    rate_limit           = optional(number, 1000000)
    alternative_ssl_domains = optional(object({
      api    = optional(list(string), [])
      health = optional(list(string), [])
    }), {})
    nodes = optional(list(object({
      count  = number
      region = optional(string)
      zone   = optional(string)
    })), [])
    os_images_override      = optional(map(string), {})
    instance_type_override  = optional(map(string), {})
    disk_snapshot_override  = optional(map(string), {})
    boot_disk_size_override = optional(map(number), {})
    data_disk_size_override = optional(map(number), {})
    allow_ip_ranges = optional(map(object({
      priority         = number
      description      = string
      src_ip_ranges    = list(string)
      action           = optional(string, "throttle")
      rate_limit_count = optional(number, 30000)
    })), {})
    allow_api_keys = optional(map(object({
      priority         = number
      description      = string
      api_key          = string
      action           = optional(string, "throttle")
      rate_limit_count = optional(number, 30000)
    })), {})
    allow_custom_rules = optional(map(object({
      priority         = number
      description      = string
      expression       = string
      action           = optional(string, "throttle")
      rate_limit_count = optional(number, 30000)
    })), {})
  })
  default = {}

  # Validation for provisioning_model
  validation {
    condition     = var.api.rate_limit >= 1 && var.api.rate_limit <= 1000000
    error_message = "Rate limit must be a positive integer between 1 and 1,000,000."
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
    boot_disk_size       = optional(number, 100)
    data_disk_size       = optional(number, 100)
    instance_type        = optional(string, "e2-standard-2")
    provisioning_model   = optional(string, "STANDARD")
    generate_external_ip = optional(bool, false)
    nodes = optional(list(object({
      count  = number
      region = optional(string)
      zone   = optional(string)
    })), [])
    os_images_override      = optional(map(string), {})
    instance_type_override  = optional(map(string), {})
    disk_snapshot_override  = optional(map(string), {})
    boot_disk_size_override = optional(map(number), {})
    data_disk_size_override = optional(map(number), {})
  })
  default = {}

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
    boot_disk_size       = optional(number, 100)
    data_disk_size       = optional(number, 100)
    instance_type        = optional(string, "e2-standard-2")
    provisioning_model   = optional(string, "STANDARD")
    generate_external_ip = optional(bool, true)
    nodes = optional(list(object({
      count  = number
      region = optional(string)
      zone   = optional(string)
    })), [])
    os_images_override      = optional(map(string), {})
    instance_type_override  = optional(map(string), {})
    disk_snapshot_override  = optional(map(string), {})
    boot_disk_size_override = optional(map(number), {})
    data_disk_size_override = optional(map(number), {})
  })
  default = {}

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
    boot_disk_size       = optional(number, 100)
    data_disk_size       = optional(number, 100)
    instance_type        = optional(string, "e2-standard-2")
    provisioning_model   = optional(string, "STANDARD")
    generate_external_ip = optional(bool, false)
    bucket_force_destroy = optional(bool, true)
    bucket_versioning    = optional(bool, true)
    alternative_ssl_domains = optional(object({
      default = optional(list(string), [])
    }), {})
    nodes = optional(list(object({
      count  = number
      region = optional(string)
      zone   = optional(string)
    })), [])
    os_images_override      = optional(map(string), {})
    instance_type_override  = optional(map(string), {})
    disk_snapshot_override  = optional(map(string), {})
    boot_disk_size_override = optional(map(number), {})
    data_disk_size_override = optional(map(number), {})
  })
  default = {}

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

variable "persistence" {
  description = "(Optional) The configuration of the persistence nodes"
  type = object({
    boot_disk_size       = optional(number, 100)
    data_disk_size       = optional(number, 100)
    instance_type        = optional(string, "e2-standard-2")
    provisioning_model   = optional(string, "STANDARD")
    generate_external_ip = optional(bool, false)
    nodes = optional(list(object({
      count  = number
      region = optional(string)
      zone   = optional(string)
    })), [])
    os_images_override      = optional(map(string), {})
    instance_type_override  = optional(map(string), {})
    disk_snapshot_override  = optional(map(string), {})
    boot_disk_size_override = optional(map(number), {})
    data_disk_size_override = optional(map(number), {})
  })
  default = {}

  # Validation for provisioning_model
  validation {
    condition     = contains(["STANDARD", "SPOT"], var.persistence.provisioning_model)
    error_message = "Provisioning model must be one of 'STANDARD' or 'SPOT'."
  }

  # Validation to check that both 'region' and 'zone' are not specified together
  validation {
    condition = alltrue([
      for node in var.persistence.nodes : (node.region != null && node.zone == null) || (node.region == null && node.zone != null)
    ])
    error_message = "You need to specify either 'region' or 'zone' for a node."
  }
}

variable "private_api" {
  description = "(Optional) The configuration of the private API nodes"
  type = map(object({
    boot_disk_size         = optional(number, 100)
    data_disk_size         = optional(number, 100)
    instance_type          = optional(string, "e2-standard-2")
    provisioning_model     = optional(string, "STANDARD")
    generate_external_ip   = optional(bool, false)
    detach_load_balancer   = optional(bool, false)
    firewall_source_ranges = optional(list(string), [])
    dns_names              = optional(list(string), [])
    alternative_ssl_domains = optional(object({
      default = optional(list(string), [])
    }), {})
    nodes = optional(list(object({
      count  = number
      region = optional(string)
      zone   = optional(string)
    })), [])
    os_images_override      = optional(map(string), {})
    instance_type_override  = optional(map(string), {})
    disk_snapshot_override  = optional(map(string), {})
    boot_disk_size_override = optional(map(number), {})
    data_disk_size_override = optional(map(number), {})
  }))
  default = {}

  # Validation for provisioning_model
  validation {
    condition     = alltrue([for key, config in var.private_api : contains(["STANDARD", "SPOT"], config.provisioning_model)])
    error_message = "Provisioning model must be one of 'STANDARD' or 'SPOT' for all private API configurations."
  }

  # Validation to check that both 'region' and 'zone' are not specified together
  validation {
    condition = alltrue([
      for key, config in var.private_api :
      alltrue([
        for node in config.nodes :
        (node.region != null && node.zone == null) || (node.region == null && node.zone != null)
      ])
    ])
    error_message = "For each private API configuration, you need to specify either 'region' or 'zone' for each node, but not both."
  }

  # Validation to ensure the length of dns_names matches the sum of all node counts
  validation {
    condition = alltrue([
      for name, config in var.private_api :
      length(config.dns_names) == sum([for node in config.nodes : node.count])
    ])
    error_message = "The length of 'dns_names' must match the total number of nodes (sum of 'count' in 'nodes')."
  }

  # Validation to ensure the length of dns_names matches the sum of all node counts
  validation {
    condition = alltrue([
      for key in keys(var.private_api) :
      !contains(["bootstrap", "api", "validator", "apps", "checkpoint", "persistence", "private-api", "sentry"], key)
    ])
    error_message = "The private-api key must NOT be one of: 'bootstrap', 'api', 'validator', 'apps', 'checkpoint', 'persistence', 'private-api', 'sentry'."
  }
}

variable "jsonrpc_allowed_sources" {
  description = "A list of CIDR blocks allowed to reach the nodes RPC port."
  type        = list(string)
  nullable    = false
  default     = []
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

variable "persistence_bucket_versioning" {
  description = "(Optional) Ebable the persistence bucket versioning."
  type        = bool
  default     = true
  nullable    = false
}

variable "performance_tests_service_account" {
  description = "Email of the performance tests service account"
  type        = string
  default     = "sa-gha-testing-001@prj-p-devops-services-tvwmrf63.iam.gserviceaccount.com"
}

variable "enable_redis" {
  description = "(Optional) Enable the Redis instance."
  type        = bool
  default     = false
  nullable    = false
}