################################################################################
# ZQ2 GCP Terraform graph resources
################################################################################

module "graphs" {
  source = "./modules/node"

  config     = var.graph
  chain_name = var.chain_name

  role         = "graph"
  labels       = local.labels
  network_tags = []

  metadata = {
    subdomain = base64encode("")
  }

  node_dns_subdomain       = var.node_dns_subdomain
  node_dns_zone_project_id = var.node_dns_zone_project_id

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "graph" {
  for_each = toset(module.graphs.zones)

  name      = "${var.chain_name}-graph-${each.key}"
  zone      = each.key
  instances = [for instance in module.graphs.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_compute_firewall" "allow_graph_external_http" {
  name    = "${var.chain_name}-graph-allow-external-http"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = concat(local.google_load_balancer_ip_ranges, [local.monitoring_ip_range])

  target_tags = [format("%s-%s", var.chain_name, "graph")]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}

resource "google_compute_health_check" "graph" {
  name = "${var.chain_name}-graph-health"

  http_health_check {
    port               = "8080"
    port_specification = "USE_FIXED_PORT"
    request_path       = "/health"
  }
}

resource "google_compute_backend_service" "graph" {
  name                  = "${var.chain_name}-graph-nodes"
  health_checks         = [google_compute_health_check.graph.id]
  port_name             = "jsonrpc"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = var.graph.detach_load_balancer ? {} : google_compute_instance_group.graph
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }
}

resource "google_compute_url_map" "graph" {
  name            = "${var.chain_name}-graph"
  default_service = google_compute_backend_service.graph.id
}

resource "google_compute_managed_ssl_certificate" "graph" {
  name = "${var.chain_name}-graph"

  managed {
    domains = ["graph.${var.subdomain}"]
  }
}

resource "google_compute_target_http_proxy" "graph" {
  name    = "${var.chain_name}-graph-target-proxy"
  url_map = google_compute_url_map.graph.id
}

resource "google_compute_target_https_proxy" "graph" {
  name             = "${var.chain_name}-graph-target-proxy"
  url_map          = google_compute_url_map.graph.id
  ssl_certificates = [google_compute_managed_ssl_certificate.graph.id]
}

data "google_compute_global_address" "graph" {
  name = "graph-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "graph_http" {
  name                  = "${var.chain_name}-graph-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.graph.id
  ip_address            = data.google_compute_global_address.graph.address
}

resource "google_compute_global_forwarding_rule" "graph_https" {
  name                  = "${var.chain_name}-graph-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.graph.id
  ip_address            = data.google_compute_global_address.graph.address
}
