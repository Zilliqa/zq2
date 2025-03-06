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
# FIREWALL POLICIES
################################################################################

resource "google_compute_firewall" "allow_ssh_from_iap" {
  name    = "${var.chain_name}-allow-ssh-from-iap"
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
  source_ranges = concat(local.google_load_balancer_ip_ranges, ["0.0.0.0/0", local.iap_ip_range])

  target_tags = [var.chain_name]

  allow {
    protocol = "tcp"
    ports    = ["4201"]
  }
}

resource "google_compute_firewall" "allow_jsonrpc_from_iap" {
  name    = "${var.chain_name}-allow-jsonrpc-from-iap"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = [local.monitoring_ip_range, local.iap_ip_range]

  target_tags = [var.chain_name]

  allow {
    protocol = "tcp"
    ports    = ["4202"]
  }
}

resource "google_compute_firewall" "allow_monitor_healthcheck" {
  name    = "${var.chain_name}-allow-monitor-healthcheck"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = [local.monitoring_ip_range]

  target_tags = [var.chain_name]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}
