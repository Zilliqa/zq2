# Add a random suffix to the compute instance names. This ensures that when they are re-created, their `self_link`
# changes and any instance groups containing them are updated.

resource "random_bytes" "generate_node_key" {
  count  = var.generate_node_key ? 1 : 0
  length = 32
}

resource "google_secret_manager_secret" "node_key" {
  count     = var.generate_node_key ? 1 : 0
  secret_id = "${var.name}-${count.index}-${random_id.name_suffix.hex}-pk"

  labels = merge(
    { "zq2-network" = var.zq2_chain_name },
    { "role" = var.role },
    { "node-name" = "${var.name}-${count.index}-${random_id.name_suffix.hex}" },
    var.labels
  )

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "node_key_version" {
  count       = var.generate_node_key ? 1 : 0
  secret      = google_secret_manager_secret.node_key[count.index].id
  secret_data = random_bytes.generate_node_key[count.index].hex
}

resource "random_bytes" "generate_reward_wallet" {
  count  = var.generate_reward_wallet ? 1 : 0
  length = 32
}

resource "google_secret_manager_secret" "reward_wallet" {
  count     = var.generate_reward_wallet ? 1 : 0
  secret_id = "${var.name}-${count.index}-${random_id.name_suffix.hex}-wallet-pk"

  labels = merge(
    { "zq2-network" = var.zq2_chain_name },
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
  count       = var.generate_reward_wallet ? 1 : 0
  secret      = google_secret_manager_secret.reward_wallet[count.index].id
  secret_data = random_bytes.generate_reward_wallet[count.index].hex
}

resource "google_compute_address" "this" {
  project = var.project_id

  name         = var.name
  region       = var.region
  network_tier = local.network_tier
}

resource "google_service_account" "this" {
  account_id = substr("sa-${var.name}", 0, 28)
}

resource "google_project_iam_member" "metric_writer" {
  project = data.google_project.this.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.this.email}"
}

resource "google_project_iam_member" "log_writer" {
  project = data.google_project.this.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.this.email}"
}

resource "google_project_iam_member" "artifact_registry_reader" {
  project = var.docker_registry_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.this.email}"
}

resource "google_project_iam_member" "secret_manager_accessor" {
  project = data.google_project.this.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.this.email}"
}

resource "google_compute_instance" "this" {
  project = var.project_id

  name                      = var.name
  machine_type              = var.instance_type
  allow_stopping_for_update = true
  zone                      = var.zone

  scheduling {
    provisioning_model = var.provisioning_model
    preemptible        = var.provisioning_model == "SPOT"
    automatic_restart  = var.provisioning_model != "SPOT"

    instance_termination_action = var.provisioning_model == "SPOT" ? "STOP" : null
  }

  labels = local.labels

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
      size  = var.disk_size
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
      type  = "pd-ssd"
    }
  }

  network_interface {
    network    = var.network_name
    subnetwork = var.subnetwork_name

    access_config {
      nat_ip = google_compute_address.this.address
    }
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  tags = local.tags

  metadata = {
    "enable-guest-attributes" = "TRUE"
    "enable-osconfig"         = "TRUE"
    "genesis_key"             = base64encode(var.genesis_key)
    "persistence_url"         = base64encode(var.persistence_url)
    "subdomain"               = base64encode(var.zq2_chain_subdomain)
    "secret_key"              = !var.generate_node_key ? "" : base64encode(google_secret_manager_secret_version.node_key_version[count.index].secret_data)
  }

  lifecycle {
    ignore_changes = [
      labels["peer-id"]
    ]
  }
}
