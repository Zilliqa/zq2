################################################################################
# ZQ2 GCP Terraform query resources
################################################################################

module "queries" {
  source = "./modules/node"

  config     = var.query
  chain_name = var.chain_name

  role         = "query"
  labels       = local.labels
  network_tags = []

  metadata = {
    subdomain = base64encode("")
  }

  node_dns_subdomain       = var.node_dns_subdomain
  node_dns_zone_project_id = var.node_dns_zone_project_id

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "query" {
  for_each = toset(module.queries.zones)

  name      = "${var.chain_name}-query-${each.key}"
  zone      = each.key
  instances = [for instance in module.queries.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_compute_firewall" "allow_query_external_http" {
  name    = "${var.chain_name}-query-allow-external-http"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = concat(local.google_load_balancer_ip_ranges, [local.monitoring_ip_range])

  target_tags = [format("%s-%s", var.chain_name, "query")]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}

resource "google_compute_health_check" "query" {
  name = "${var.chain_name}-query-health"

  http_health_check {
    port               = "8080"
    port_specification = "USE_FIXED_PORT"
    request_path       = "/health"
  }
}

resource "google_compute_backend_service" "query" {
  name                  = "${var.chain_name}-query-nodes"
  health_checks         = [google_compute_health_check.query.id]
  port_name             = "jsonrpc"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = var.query.detach_load_balancer ? {} : google_compute_instance_group.query
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }
}

resource "google_compute_url_map" "query" {
  name            = "${var.chain_name}-query"
  default_service = google_compute_backend_service.query.id
}

resource "google_compute_managed_ssl_certificate" "query" {
  name = "${var.chain_name}-query"

  managed {
    domains = ["query.${var.subdomain}"]
  }
}

resource "google_compute_target_http_proxy" "query" {
  name    = "${var.chain_name}-query-target-proxy"
  url_map = google_compute_url_map.query.id
}

resource "google_compute_target_https_proxy" "query" {
  name             = "${var.chain_name}-query-target-proxy"
  url_map          = google_compute_url_map.query.id
  ssl_certificates = [google_compute_managed_ssl_certificate.query.id]
}

data "google_compute_global_address" "query" {
  name = "query-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "query_http" {
  name                  = "${var.chain_name}-query-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.query.id
  ip_address            = data.google_compute_global_address.query.address
}

resource "google_compute_global_forwarding_rule" "query_https" {
  name                  = "${var.chain_name}-query-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.query.id
  ip_address            = data.google_compute_global_address.query.address
}
