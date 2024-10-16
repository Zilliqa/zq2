# Add a random suffix to the compute instance names. This ensures that when they are re-created, their `self_link`
# changes and any instance groups containing them are updated.

resource "random_bytes" "generate_node_key" {
  for_each = var.generate_node_key ? local.instances_map : {}

  length = 32
}

resource "google_secret_manager_secret" "node_key" {
  for_each = var.generate_node_key ? local.instances_map : {}

  secret_id = "${each.value.resource_name}-pk"

  labels = merge(local.labels, { "node-name" = each.value.resource_name })

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "node_key_version" {
  for_each = var.generate_node_key ? local.instances_map : {}

  secret      = google_secret_manager_secret.node_key[each.value.resource_id].id
  secret_data = random_bytes.generate_node_key[each.value.resource_id].hex
}

resource "random_bytes" "generate_reward_wallet" {
  for_each = var.generate_reward_wallet ? local.instances_map : {}

  length = 32
}

resource "google_secret_manager_secret" "reward_wallet" {
  for_each = var.generate_reward_wallet ? local.instances_map : {}

  secret_id = "${each.value.resource_name}-wallet-pk"

  labels = merge(
    local.labels,
    { "node-name" = each.value.resource_name },
    { "is_reward_wallet" = true },
  )

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "reward_wallet_version" {
  for_each = var.generate_reward_wallet ? local.instances_map : {}

  secret      = google_secret_manager_secret.reward_wallet[each.value.resource_id].id
  secret_data = random_bytes.generate_reward_wallet[each.value.resource_id].hex
}

resource "random_id" "name_suffix" {
  byte_length = 2

  # Enable keepers to force reprovisioning the module resources
  # keepers = var.metadata
}

resource "google_service_account" "this" {
  account_id = substr(local.resource_name, 0, 28)
}

resource "google_project_iam_member" "this" {
  for_each = toset(var.service_account_iam)

  project = split("=>", each.value)[1]
  role    = split("=>", each.value)[0]
  member  = "serviceAccount:${google_service_account.this.email}"
}

resource "google_compute_address" "external_regional" {
  for_each = var.config.generate_external_ip ? local.instances_map : {}

  project = data.google_project.current.project_id

  name         = each.value.resource_name
  region       = each.value.region
  network_tier = "PREMIUM"

  labels = merge(local.labels, { "node-name" = each.value.resource_name })
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

  labels = merge(local.labels, { "node-name" = each.value.resource_name })

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
    subnetwork = data.google_compute_subnetworks.default[each.value.region].subnetworks[0].name

    dynamic "access_config" {
      for_each = [var.role == "validator" ? 1 : 0] # Always create the access_config block for validators
      content {
        nat_ip = var.config.generate_external_ip ? google_compute_address.external_regional[each.value.resource_id].address : null
      }
    }
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  tags = local.network_tags

  metadata = merge(
    {
      "enable-guest-attributes" = "TRUE"
      "enable-osconfig"         = "TRUE"
      "secret_key"              = !var.generate_node_key ? "" : base64encode(google_secret_manager_secret_version.node_key_version[each.value.resource_id].secret_data)
    },
    var.metadata,
  )

  lifecycle {
    ignore_changes = [
      labels["peer-id"]
    ]
  }
}

resource "google_dns_record_set" "this" {
  for_each = local.instances_map

  project      = var.node_dns_zone_project_id
  managed_zone = local.node_dns_zone_name
  name         = "${google_compute_instance.this[each.value.resource_id].name}.${var.node_dns_subdomain}."
  type         = "A"
  ttl          = "60"

  rrdatas = [google_compute_instance.this[each.value.resource_id].network_interface[0].access_config[0].nat_ip]

  depends_on = [google_compute_instance.this]
}
