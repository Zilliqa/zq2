################################################################################
# ZQ2 GCP Terraform main resources
################################################################################

resource "google_project_service" "secret_manager" {
  service            = "secretmanager.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

resource "google_project_service" "osconfig" {
  service            = "osconfig.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

resource "google_project_service" "certificate_manager" {
  service            = "certificatemanager.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

resource "google_project_service" "cloud_dns" {
  service            = "dns.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

################################################################################
# PERSISTENCE BUCKET
################################################################################

resource "google_storage_bucket" "persistence" {
  name     = join("-", compact([var.chain_name, "persistence"]))
  project  = var.project_id
  location = var.region
  labels   = local.labels

  force_destroy               = var.persistence_bucket_force_destroy
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"

  versioning {
    enabled = true
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
    condition {
      age = 7
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
    condition {
      age = 37 # 7 days in Standard + 30 days in Nearline
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
    condition {
      age = 127 # 37 days + 90 days in Coldline
    }
  }
}

resource "google_storage_bucket_iam_binding" "persistence_bucket_admins" {
  bucket = google_storage_bucket.persistence.name
  role   = "roles/storage.objectAdmin"
  members = [
    "serviceAccount:${module.bootstraps.service_account.email}",
    "serviceAccount:${module.validators.service_account.email}",
    "serviceAccount:${module.apis.service_account.email}",
    "serviceAccount:${module.checkpoints.service_account.email}",
    "serviceAccount:${module.persistences.service_account.email}",
    "serviceAccount:${module.queries.service_account.email}"
  ]
}

################################################################################
# FIREWALL POLICIES
################################################################################

resource "google_compute_firewall" "allow_ingress_from_iap" {
  name    = "${var.chain_name}-allow-ingress-from-iap"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = [local.iap_ip_range]

  target_tags = [var.chain_name]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_p2p" {
  name    = "${var.chain_name}-allow-p2p"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  target_tags = [var.chain_name]

  allow {
    protocol = "tcp"
    ports    = ["3333"]
  }

  allow {
    protocol = "udp"
    ports    = ["3333"]
  }
}

resource "google_compute_firewall" "allow_external_jsonrpc" {
  name    = "${var.chain_name}-allow-external-jsonrpc"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  target_tags = [var.chain_name]

  allow {
    protocol = "tcp"
    ports    = ["4201"]
  }
}

resource "google_compute_firewall" "allow_monitor_healthcheck" {
  name    = "${var.chain_name}-allow-monitor-healthcheck"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = [local.monitoring_ip_range]

  target_tags = [format("%s", var.chain_name)]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}
