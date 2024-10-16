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

## Enable the certificate manager API ##
resource "google_project_service" "certificate_manager" {
  service            = "certificatemanager.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

## Enable the Cloud DNS API ##
resource "google_project_service" "cloud_dns" {
  service            = "dns.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

resource "random_bytes" "generate_genesis_key" {
  length = 32
}

resource "google_secret_manager_secret" "genesis_key" {
  secret_id = "${var.network_name}-genesis-key"

  labels = merge({ "role" = "genesis" }, local.labels)

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "genesis_key_version" {
  secret      = google_secret_manager_secret.genesis_key.id
  secret_data = random_bytes.generate_genesis_key.hex
}

resource "google_storage_bucket" "persistence" {
  name     = join("-", compact([var.network_name, "persistence"]))
  project  = var.project_id
  location = var.region
  labels   = local.labels

  force_destroy               = var.persistence_bucket_force_destroy
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"

  versioning {
    enabled = true
  }
}

resource "google_compute_firewall" "allow_ingress_from_iap" {
  name    = "${var.network_name}-allow-ingress-from-iap"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]

  target_tags = [var.network_name]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_p2p" {
  name    = "${var.network_name}-allow-p2p"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  target_tags = [var.network_name]

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
  name    = "${var.network_name}-allow-external-jsonrpc"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  target_tags = [var.network_name]

  allow {
    protocol = "tcp"
    ports    = ["4201"]
  }
}
