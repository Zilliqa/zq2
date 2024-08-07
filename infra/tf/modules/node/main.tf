# Add a random suffix to the compute instance names. This ensures that when they are re-created, their `self_link`
# changes and any instance groups containing them are updated.

resource "random_bytes" "generate_node_key" {
  count  = !var.generate_node_key ? 0 : var.vm_num
  length = 32
}

resource "google_secret_manager_secret" "node_key" {
  count     = !var.generate_node_key ? 0 : var.vm_num
  secret_id = "${var.name}-${count.index}-${random_id.name_suffix.hex}-pk"

  labels = merge(
    { "zq2-network" = var.zq_network_name },
    { "role" = var.role },
    { "node-name" = "${var.name}-${count.index}-${random_id.name_suffix.hex}" },
    var.labels
  )

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "node_key_version" {
  count       = !var.generate_node_key ? 0 : var.vm_num
  secret      = google_secret_manager_secret.node_key[count.index].id
  secret_data = random_bytes.generate_node_key[count.index].hex
}

resource "random_bytes" "generate_reward_wallet" {
  count  = !var.generate_reward_wallet ? 0 : var.vm_num
  length = 32
}

resource "google_secret_manager_secret" "reward_wallet" {
  count     = !var.generate_reward_wallet ? 0 : var.vm_num
  secret_id = "${var.name}-${count.index}-${random_id.name_suffix.hex}-wallet-pk"

  labels = merge(
    { "zq2-network" = var.zq_network_name },
    { "role" = var.role },
    { "node-name" = "${var.name}-${count.index}-${random_id.name_suffix.hex}" },
    { "is_reward_wallet" = true },
    var.labels
  )

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "reward_wallet_version" {
  count       = !var.generate_reward_wallet ? 0 : var.vm_num
  secret      = google_secret_manager_secret.reward_wallet[count.index].id
  secret_data = random_bytes.generate_reward_wallet[count.index].hex
}

resource "random_id" "name_suffix" {
  byte_length = 2

  keepers = {
    name                  = var.name
    service_account_email = var.service_account_email
    network_name          = var.network_name
    subnetwork_name       = var.subnetwork_name
    # docker_image          = var.docker_image
    # otterscan_image       = var.otterscan_image
    # spout_image           = var.spout_image
  }
}

resource "google_compute_instance" "this" {
  count = var.vm_num

  name                      = "${var.name}-${count.index}-${random_id.name_suffix.hex}"
  machine_type              = var.node_type
  allow_stopping_for_update = true
  zone                      = length(var.node_zones) > 1 ? sort(var.node_zones)[count.index % length(var.node_zones)] : var.node_zones[count.index % length(var.node_zones)]

  labels = merge({ "zq2-network" = var.zq_network_name },
  { "role" = var.role }, { "node-name" = "${var.name}-${count.index}-${random_id.name_suffix.hex}" }, var.labels)

  service_account {
    email = var.service_account_email
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
      size  = 256
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      type  = "pd-ssd"
    }
  }

  network_interface {
    network    = var.network_name
    subnetwork = var.subnetwork_name

    dynamic "access_config" {
      for_each = [var.role == "validator" ? 1 : 0] # Always create the access_config block for validators
      content {
        # Conditionally set nat_ip only if var.external_ip is not empty
        nat_ip = var.external_ip != "" ? var.external_ip : null
      }
    }
  }

  metadata = {
    "enable-guest-attributes"   = "TRUE"
    "enable-osconfig"           = "TRUE"
    "genesis_key"               = base64encode(var.genesis_key)
    "persistence_url"           = base64encode(var.persistence_url)
    "subdomain"                 = base64encode(var.subdomain)
    "secret_key"                = !var.generate_node_key ? "" : base64encode(google_secret_manager_secret_version.node_key_version[count.index].secret_data)
    "secret_id"                 = !var.generate_node_key ? "" : google_secret_manager_secret_version.node_key_version[count.index].id
    "reward_wallet_private_key" = !var.generate_reward_wallet ? "" : base64encode(google_secret_manager_secret_version.reward_wallet_version[count.index].secret_data)
    "reward_wallet_secret_id"   = !var.generate_reward_wallet ? "" : google_secret_manager_secret_version.reward_wallet_version[count.index].id
  }
}

resource "google_dns_record_set" "this" {
  for_each = { for idx, instance in google_compute_instance.this : idx => instance }

  project      = var.dns_zone_project_id
  managed_zone = local.nodes_domain_name
  name         = each.key != "@" ? "${each.value.name}.${var.nodes_dns_zone_name}." : "${var.nodes_dns_zone_name}."
  type         = "A"
  ttl          = try(each.value.ttl, "60")

  rrdatas = [each.value.network_interface[0].access_config[0].nat_ip]
}
