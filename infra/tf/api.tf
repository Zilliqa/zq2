################################################################################
# API INSTANCES
################################################################################

module "apis" {
  source = "./modules/node"

  config     = var.api
  chain_name = var.chain_name

  role         = "api"
  labels       = local.labels
  network_tags = []

  metadata = {
    subdomain = base64encode(var.subdomain)
  }

  node_dns_subdomain       = var.node_dns_subdomain
  node_dns_zone_project_id = var.node_dns_zone_project_id

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "api" {
  for_each = toset(module.apis.zones)

  name      = "${var.chain_name}-api-${each.key}"
  zone      = each.key
  instances = [for instance in module.apis.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_compute_firewall" "allow_api_external_http" {
  name    = "${var.chain_name}-api-allow-external-http"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = concat(local.google_load_balancer_ip_ranges, [local.monitoring_ip_range])

  target_tags = [format("%s-%s", var.chain_name, "api")]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}

resource "google_compute_health_check" "api" {
  name = "${var.chain_name}-jsonrpc"

  http_health_check {
    port               = "8080"
    port_specification = "USE_FIXED_PORT"
    request_path       = "/health"
  }
}

resource "google_compute_backend_service" "api" {
  name                  = "${var.chain_name}-api-nodes"
  health_checks         = [google_compute_health_check.api.id]
  port_name             = "jsonrpc"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = var.api.detach_load_balancer ? {} : google_compute_instance_group.api
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }
}

resource "google_compute_url_map" "api" {
  name            = var.chain_name
  default_service = google_compute_backend_service.api.id
}

resource "google_compute_managed_ssl_certificate" "api" {
  name = "${var.chain_name}-api"

  managed {
    domains = ["api.${var.subdomain}"]
  }
}

resource "google_compute_target_http_proxy" "api" {
  name    = "${var.chain_name}-target-proxy"
  url_map = google_compute_url_map.api.id
}

resource "google_compute_target_https_proxy" "api" {
  name             = "${var.chain_name}-target-proxy"
  url_map          = google_compute_url_map.api.id
  ssl_certificates = [google_compute_managed_ssl_certificate.api.id]
}

data "google_compute_global_address" "api" {
  name = "api-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "api_http" {
  name                  = "${var.chain_name}-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.api.id
  ip_address            = data.google_compute_global_address.api.address
}

resource "google_compute_global_forwarding_rule" "api_https" {
  name                  = "${var.chain_name}-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.api.id
  ip_address            = data.google_compute_global_address.api.address
}
