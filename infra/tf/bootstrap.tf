################################################################################
# BOOTSTRAP INSTANCES
################################################################################

module "bootstraps" {
  source = "./modules/node"

  config     = var.bootstrap
  chain_name = var.chain_name

  role         = "bootstrap"
  labels       = local.labels
  network_tags = []

  metadata = {
    subdomain = base64encode("")
  }

  node_dns_subdomain       = var.node_dns_subdomain
  node_dns_zone_project_id = var.node_dns_zone_project_id

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "bootstrap" {
  for_each = toset(module.bootstraps.zones)

  name      = "${var.chain_name}-bootstrap-${each.key}"
  zone      = each.key
  instances = [for instance in module.bootstraps.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }

  named_port {
    name = "peer"
    port = "3333"
  }
}

resource "google_compute_firewall" "allow_bootstrap_external_http" {
  name    = "${var.chain_name}-bootstrap-allow-external-http"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = concat(local.google_load_balancer_ip_ranges, [local.monitoring_ip_range])

  target_tags = [format("%s-%s", var.chain_name, "bootstrap")]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}

resource "google_compute_health_check" "bootstrap" {
  name = "${var.chain_name}-bootstrap-health"

  http_health_check {
    port               = "8080"
    port_specification = "USE_FIXED_PORT"
    request_path       = "/health"
  }
}

resource "google_compute_backend_service" "bootstrap" {
  name                  = "${var.chain_name}-bootstrap-nodes"
  health_checks         = [google_compute_health_check.bootstrap.id]
  port_name             = "peer"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  protocol              = "TCP"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = var.bootstrap.detach_load_balancer ? {} : google_compute_instance_group.bootstrap
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }
}

resource "google_compute_target_tcp_proxy" "bootstrap" {
  name            = "${var.chain_name}-bootstrap-target-proxy"
  backend_service = google_compute_backend_service.bootstrap.id
}

data "google_compute_global_address" "bootstrap" {
  name = "bootstrap-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "bootstrap" {
  name                  = "${var.chain_name}-bootstrap-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "3333"
  target                = google_compute_target_tcp_proxy.bootstrap.id
  ip_address            = data.google_compute_global_address.bootstrap.address
}
