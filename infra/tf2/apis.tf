################################################################################
# ZQ2 GCP Terraform api resources
################################################################################

resource "google_service_account" "api" {
  account_id = substr("${var.network_name}-api", 0, 28)
}

resource "google_project_iam_member" "api_metric_writer" {
  project = data.google_project.this.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "api_log_writer" {
  project = data.google_project.this.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "api_artifact_registry_reader" {
  project = var.gcp_docker_registry_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "api_secret_manager_accessor" {
  project = data.google_project.this.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.api.email}"
}

module "apis" {
  source = "./modules/node"
  vm_num = var.api_node_count

  name                  = "${var.network_name}-node-api"
  service_account_email = google_service_account.api.email
  dns_zone_project_id   = var.dns_zone_project_id
  nodes_dns_zone_name   = var.nodes_dns_zone_name
  network_name          = local.network_name
  node_zones            = local.default_zones
  subnetwork_name       = data.google_compute_subnetwork.default.name
  persistence_url       = var.persistence_url
  role                  = "api"
  zq_network_name       = var.network_name
  provisioning_model    = var.provisioning_model
  node_type             = var.node_type
}

resource "google_compute_instance_group" "api" {
  for_each = toset(local.default_zones)

  name      = "${var.network_name}-api-${each.key}"
  zone      = each.key
  instances = [for instance in module.apis.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_compute_firewall" "allow_api_external_http" {
  name    = "${var.network_name}-api-allow-external-http"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = local.google_load_balancer_ip_ranges

  target_tags = [format("%s-%s", var.network_name, "api")]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}

resource "google_compute_health_check" "api" {
  name = "${var.network_name}-jsonrpc"

  http_health_check {
    port               = "8080"
    port_specification = "USE_FIXED_PORT"
    request_path       = "/health"
  }
}

resource "google_compute_backend_service" "api" {
  name                  = "${var.network_name}-api-nodes"
  health_checks         = [google_compute_health_check.api.id]
  port_name             = "jsonrpc"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = google_compute_instance_group.api
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }
}

resource "google_compute_url_map" "api" {
  name            = var.network_name
  default_service = google_compute_backend_service.api.id
}

resource "google_compute_target_http_proxy" "api" {
  name    = "${var.network_name}-target-proxy"
  url_map = google_compute_url_map.api.id
}

resource "google_compute_target_https_proxy" "api" {
  name             = "${var.network_name}-target-proxy"
  url_map          = google_compute_url_map.api.id
  ssl_certificates = [google_compute_managed_ssl_certificate.api.id]
}

data "google_compute_global_address" "api" {
  name = "api-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "api_http" {
  name                  = "${var.network_name}-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.api.id
  ip_address            = data.google_compute_global_address.api.address
}

resource "google_compute_global_forwarding_rule" "api_https" {
  name                  = "${var.network_name}-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.api.id
  ip_address            = data.google_compute_global_address.api.address
}

resource "google_compute_managed_ssl_certificate" "api" {
  name = "${var.network_name}-api"

  managed {
    domains = ["api.${var.subdomain}"]
  }
}
