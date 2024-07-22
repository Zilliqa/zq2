variable "name" {
  type     = string
  nullable = false
}

variable "service_account_email" {
  type     = string
  nullable = false
}

variable "vm_num" {
  type     = number
  nullable = false
  default  = 1
}

variable "network_name" {
  type     = string
  nullable = false
}

variable "subnetwork_name" {
  type     = string
  nullable = false
}


variable "subdomain" {
  description = "(Optional) ZQ2 network subdomain"
  type        = string
  default     = ""
}

variable "docker_image" {
  description = "(Option): ZQ2 validator docker image"
  type        = string
  default     = ""
}

variable "config" {
  type     = string
}

variable "secret_key" {
  type     = string
}

variable "genesis_key" {
  type = string
  default = ""
}


variable "node_type" {
  type     = string
  default  = "e2-standard-2"
  nullable = false
}

variable "node_zone" {
  type     = string
  default  = "europe-west2-a"
  nullable = false
}

variable "persistence_url" {
  type     = string
  nullable = true
}

variable "zq_network_name" {
  type     = string
  nullable = false
}

variable "region" {
  description = "The region ID to host the network in"
  type        = string
  default     = "europe-west2"
}

variable "role" {
  description = "VM role"
  default     = "validator"
  validation {
    condition     = contains(["validator", "apps"], var.role)
    error_message = "The role value must be one of 'validator' or 'apps'."
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

variable "otterscan_image" {
  description = "(Optional): Otterscan docker image url (incl. version)"
  type        = string
  default     = ""
}

variable "spout_image" {
  description = "(Optional): spout docker image url (incl. version)"
  type        = string
  default     = ""
}

# Add a random suffix to the compute instance names. This ensures that when they are re-created, their `self_link`
# changes and any instance groups containing them are updated.
resource "random_id" "name_suffix" {
  byte_length = 2

  keepers = {
    name                  = var.name
    service_account_email = var.service_account_email
    network_name          = var.network_name
    subnetwork_name       = var.subnetwork_name
    docker_image          = var.docker_image
    otterscan_image       = var.otterscan_image
    spout_image           = var.spout_image
    config                = var.config
    secret_key            = var.secret_key
  }
}

resource "google_compute_instance" "this" {
  count = var.vm_num

  name                      = "${var.name}-${count.index}-${random_id.name_suffix.hex}"
  machine_type              = var.node_type
  allow_stopping_for_update = true
  zone                      = var.node_zone
  labels = merge({ "zq2-network" = var.zq_network_name },
  { "role" = var.role }, { "node-name" = "${var.name}-${count.index}-${random_id.name_suffix.hex}" }, var.labels)

  service_account {
    email = var.service_account_email
    scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/compute", // REMOVE
    ]
  }

  boot_disk {
    initialize_params {
      size  = 256
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      type  = "pd-ssd"
    }
  }

  network_interface {
    network    = var.network_name
    subnetwork = var.subnetwork_name

    dynamic "access_config" {
      for_each = [ var.role == "validator" ? 1 : 0 ] # Always create the access_config block for validators
      content {
        # Conditionally set nat_ip only if var.external_ip is not empty
        nat_ip = var.external_ip != "" ? var.external_ip : null
      }
    }
  }

  metadata = {
    "enable-guest-attributes" = "TRUE"
    "enable-osconfig"         = "TRUE"
    "genesis_key"             = base64encode(var.genesis_key)
  }

  metadata_startup_script = templatefile("${path.module}/scripts/node_provision.py.tpl",
    {
      config          = var.config
      secret_key      = var.secret_key
      genesis_key     = var.genesis_key
      docker_image    = var.docker_image
      persistence_url = var.persistence_url
      otterscan_image = var.otterscan_image
      spout_image     = var.spout_image
      subdomain       = var.subdomain
      role            = var.role
    }
  )
}

output "id" {
  value = google_compute_instance.this[*].id
}

output "self_link" {
  value = google_compute_instance.this[*].self_link
}

output "network_ip" {
  value = google_compute_instance.this[*].network_interface[0].network_ip
}
