################################################################################
# ZQ2 GCP Terraform main resources
################################################################################

resource "google_compute_firewall" "allow_apps_ingress_from_iap" {
  name    = "${var.network_name}-allow-apps-ingress-from-iap"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_apps_external_http" {
  name    = "${var.network_name}-apps-allow-external-http"
  network = local.network_name


  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["80", "8080"]
  }
}

resource "google_compute_firewall" "allow_apps_external_https" {
  name    = "${var.network_name}-apps-allow-external-https"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_service_account" "apps" {
  account_id = substr("${var.network_name}-apps", 0, 28)
}

data "google_project" "apps" {}

resource "google_project_iam_member" "apps_metric_writer" {
  project = data.google_project.apps.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.apps.email}"
}

resource "google_project_iam_member" "apps_log_writer" {
  project = data.google_project.apps.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.apps.email}"
}

resource "google_project_iam_member" "apps_artifact_registry_reader" {
  project = var.gcp_docker_registry_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.apps.email}"
}

resource "google_project_iam_member" "apps_secret_manager_accessor" {
  project = data.google_project.apps.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.apps.email}"
}

module "apps" {
  source = "./modules/node"
  vm_num = var.apps_node_count

  role                  = "apps"
  name                  = "${var.network_name}-apps"
  service_account_email = google_service_account.apps.email
  dns_zone_project_id   = var.dns_zone_project_id
  nodes_dns_zone_name   = var.nodes_dns_zone_name
  network_name          = local.network_name
  node_zones            = local.default_zones
  subnetwork_name       = data.google_compute_subnetwork.default.name
  subdomain             = var.subdomain
  generate_node_key     = false
  persistence_url       = ""
  genesis_key           = local.genesis_key
  node_type             = var.apps_node_type

  zq_network_name = var.network_name
}

resource "google_project_service" "osconfig_apps" {
  service = "osconfig.googleapis.com"

  disable_on_destroy = false
}

resource "google_compute_managed_ssl_certificate" "apps" {
  name = "${var.network_name}-apps"

  managed {
    domains = ["explorer.${var.subdomain}", "faucet.${var.subdomain}"]
  }
}

resource "google_compute_instance_group" "apps" {
  for_each = toset(local.default_zones)

  name      = "${var.network_name}-apps-${each.key}"
  zone      = each.key
  instances = [for instance in module.apps.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "otterscan"
    port = "80"
  }

  named_port {
    name = "spout"
    port = "8080"
  }
}

resource "google_compute_backend_service" "otterscan" {
  name                  = "${var.network_name}-apps-otterscan"
  health_checks         = [google_compute_health_check.otterscan.id]
  port_name             = "otterscan"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = google_compute_instance_group.apps
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }
}

resource "google_compute_health_check" "otterscan" {
  name = "${var.network_name}-otterscan"

  http_health_check {
    port_name          = "otterscan"
    port_specification = "USE_NAMED_PORT"
    request_path       = "/"
  }
}

resource "google_compute_backend_service" "spout" {
  name                  = "${var.network_name}-apps-spout"
  health_checks         = [google_compute_health_check.spout.id]
  port_name             = "spout"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = google_compute_instance_group.apps
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }
}

resource "google_compute_health_check" "spout" {
  name = "${var.network_name}-spout"

  http_health_check {
    port_name          = "spout"
    port_specification = "USE_NAMED_PORT"
    request_path       = "/"
  }
}

resource "google_compute_url_map" "apps" {
  name            = "${var.network_name}-apps"
  default_service = google_compute_backend_service.otterscan.id

  host_rule {
    hosts        = ["explorer.${var.subdomain}"]
    path_matcher = "explorer"
  }

  host_rule {
    hosts        = ["faucet.${var.subdomain}"]
    path_matcher = "faucet"
  }

  path_matcher {
    name            = "explorer"
    default_service = google_compute_backend_service.otterscan.id
  }

  path_matcher {
    name            = "faucet"
    default_service = google_compute_backend_service.spout.id
  }
}

resource "google_compute_target_http_proxy" "apps" {
  name    = "${var.network_name}-apps-target-proxy"
  url_map = google_compute_url_map.apps.id
}

resource "google_compute_target_https_proxy" "apps" {
  name             = "${var.network_name}-apps-target-proxy"
  url_map          = google_compute_url_map.apps.id
  ssl_certificates = [google_compute_managed_ssl_certificate.apps.id]
}

data "google_compute_global_address" "explorer" {
  name = "explorer-${replace(var.subdomain, ".", "-")}"
}

data "google_compute_global_address" "faucet" {
  name = "faucet-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "otterscan_http" {
  name                  = "${var.network_name}-otter-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.apps.id
  ip_address            = data.google_compute_global_address.explorer.address
}

resource "google_compute_global_forwarding_rule" "otter_https" {
  name                  = "${var.network_name}-otter-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.apps.id
  ip_address            = data.google_compute_global_address.explorer.address
}

resource "google_compute_global_forwarding_rule" "faucet_http" {
  name                  = "${var.network_name}-faucet-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.apps.id
  ip_address            = data.google_compute_global_address.faucet.address
}

resource "google_compute_global_forwarding_rule" "faucet_https" {
  name                  = "${var.network_name}-faucet-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.apps.id
  ip_address            = data.google_compute_global_address.faucet.address
}
