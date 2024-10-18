# Add a random suffix to the compute instance names. This ensures that when they are re-created, their `self_link`
# changes and any instance groups containing them are updated.

resource "random_id" "name_suffix" {
  byte_length = 2

  keepers = {
    genesis_key     = var.genesis_key
    persistence_url = var.persistence_url
  }
}

resource "google_service_account" "this" {
  account_id = substr(local.resource_name, 0, 28)
}

resource "google_project_iam_member" "metric_writer" {
  project = data.google_project.current.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.this.email}"
}

resource "google_project_iam_member" "log_writer" {
  project = data.google_project.current.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.this.email}"
}

resource "google_project_iam_member" "artifact_registry_reader" {
  project = var.gcp_docker_registry_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.this.email}"
}

resource "google_project_iam_member" "secret_manager_accessor" {
  project = data.google_project.current.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.this.email}"
}

resource "google_compute_address" "external_regional" {
  for_each = local.instances_map

  project = data.google_project.current.project_id

  name         = each.value.resource_name
  region       = each.value.region
  network_tier = "PREMIUM"
}

resource "google_compute_instance" "this" {
  for_each = local.instances_map

  name                      = each.value.resource_name
  machine_type              = var.config.instance_type
  allow_stopping_for_update = true
  zone                      = each.value.zone

  scheduling {
    provisioning_model = var.config.provisioning_model
    preemptible        = var.config.provisioning_model == "SPOT"
    automatic_restart  = var.config.provisioning_model != "SPOT"

    instance_termination_action = var.config.provisioning_model == "SPOT" ? "STOP" : null
  }

  labels = merge(local.labels, { "node-name" = each.value.resource_name})

  service_account {
    email = google_service_account.this.email
    scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/compute", # REMOVE
    ]
  }

  boot_disk {
    initialize_params {
      size  = var.config.disk_size
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      type  = "pd-ssd"
    }
  }

  network_interface {
    network    = data.google_compute_subnetworks.default[each.value.region].subnetworks[0].network_self_link
    subnetwork    = data.google_compute_subnetworks.default[each.value.region].subnetworks[0].name

    dynamic "access_config" {
      for_each = [var.role == "validator" ? 1 : 0] # Always create the access_config block for validators
      content {
        nat_ip = google_compute_address.external_regional[each.value.resource_name].address
      }
    }
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  tags = local.network_tags

  metadata = {
    "enable-guest-attributes"   = "TRUE"
    "enable-osconfig"           = "TRUE"
    "genesis_key"               = base64encode(var.genesis_key)
    "persistence_url"           = base64encode(var.persistence_url)
    "subdomain"                 = base64encode(var.chain_subdomain)
    # "secret_key"                = !var.generate_node_key ? "" : base64encode(google_secret_manager_secret_version.node_key_version[count.index].secret_data)
    # "secret_id"                 = !var.generate_node_key ? "" : google_secret_manager_secret_version.node_key_version[count.index].id
    # "reward_wallet_private_key" = !var.generate_reward_wallet ? "" : base64encode(google_secret_manager_secret_version.reward_wallet_version[count.index].secret_data)
    # "reward_wallet_secret_id"   = !var.generate_reward_wallet ? "" : google_secret_manager_secret_version.reward_wallet_version[count.index].id
  }

  lifecycle {
    ignore_changes = [
      labels["peer-id"]
    ]
  }
}

# resource "google_compute_instance_group" "apps2" {
#   for_each = toset(local.default_zones)

#   name      = "${var.chain_name}-apps2-${each.key}"
#   zone      = each.key
#   instances = [for instance in module.apps.instances : instance.self_link if instance.zone == each.key]

#   named_port {
#     name = "otterscan"
#     port = "80"
#   }

#   named_port {
#     name = "spout"
#     port = "8080"
#   }
# }

resource "google_dns_record_set" "this" {
  for_each = { for instance in google_compute_instance.this : instance.name => instance }

  project      = var.node_dns_zone_project_id
  managed_zone = local.node_dns_zone_name
  name         = "${each.value.name}.${var.node_dns_subdomain}."
  type         = "A"
  ttl          = "60"

  rrdatas = [each.value.network_interface[0].access_config[0].nat_ip]
}

# resource "random_bytes" "generate_node_key" {
#   count  = var.generate_node_key ? length(local.instances) : 0

#   length = 32
# }

# resource "google_secret_manager_secret" "node_key" {
#   count  = var.generate_node_key ? length(local.instances) : 0

#   secret_id = "${local.resource_name}-${count.index}-pk"

#   labels = merge(
#     { "zq2-network" = var.chain_name },
#     { "role" = var.role },
#     { "node-name" = "${local.resource_name}" },
#     var.labels
#   )

#   replication {
#     auto {}
#   }
# }

# resource "google_secret_manager_secret_version" "node_key_version" {
#   count       = !var.generate_node_key ? 0 : var.vm_num
#   secret      = google_secret_manager_secret.node_key[count.index].id
#   secret_data = random_bytes.generate_node_key[count.index].hex
# }

# resource "random_bytes" "generate_reward_wallet" {
#   count  = !var.generate_reward_wallet ? 0 : var.vm_num
#   length = 32
# }

# resource "google_secret_manager_secret" "reward_wallet" {
#   count     = !var.generate_reward_wallet ? 0 : var.vm_num
#   secret_id = "${var.name}-${count.index}-${random_id.name_suffix.hex}-wallet-pk"

#   labels = merge(
#     { "zq2-network" = var.zq_network_name },
#     { "role" = var.role },
#     { "node-name" = "${var.name}-${count.index}-${random_id.name_suffix.hex}" },
#     { "is_reward_wallet" = true },
#     var.labels
#   )

#   replication {
#     auto {}
#   }
# }

# resource "google_secret_manager_secret_version" "reward_wallet_version" {
#   count       = !var.generate_reward_wallet ? 0 : var.vm_num
#   secret      = google_secret_manager_secret.reward_wallet[count.index].id
#   secret_data = random_bytes.generate_reward_wallet[count.index].hex
# }
