################################################################################
# ZQ2 GCP Terraform apps resources
################################################################################

resource "google_compute_firewall" "allow_apps_external_http" {
  name    = "${var.chain_name}-apps-allow-external-http"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  target_tags = [format("%s-%s", var.chain_name, "apps")]

  allow {
    protocol = "tcp"
    ports    = ["80", "8080"]
  }
}

resource "google_compute_firewall" "allow_apps_external_https" {
  name    = "${var.chain_name}-apps-allow-external-https"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  target_tags = [format("%s-%s", var.chain_name, "apps")]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

module "apps" {
  source = "./modules/node"

  config     = var.apps
  chain_name = var.chain_name

  role                   = "apps"
  labels                 = {}
  network_tags           = []
  generate_node_key      = false
  generate_reward_wallet = false

  metadata = {
    persistence_url = base64encode("")
    subdomain       = base64encode(var.subdomain)
    genesis_key     = base64encode(local.genesis_key)
  }

  node_dns_subdomain       = var.node_dns_subdomain
  node_dns_zone_project_id = var.node_dns_zone_project_id

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "apps" {
  for_each = toset(module.apps.zones)

  name      = "${var.chain_name}-apps-${each.key}"
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

resource "google_compute_health_check" "otterscan" {
  name = "${var.chain_name}-otterscan"

  http_health_check {
    port_name          = "otterscan"
    port_specification = "USE_NAMED_PORT"
    request_path       = "/"
  }
}

resource "google_compute_health_check" "spout" {
  name = "${var.chain_name}-spout"

  http_health_check {
    port_name          = "spout"
    port_specification = "USE_NAMED_PORT"
    request_path       = "/"
  }
}

resource "google_compute_backend_service" "otterscan" {
  name                  = "${var.chain_name}-apps-otterscan"
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

resource "google_compute_backend_service" "spout" {
  name                  = "${var.chain_name}-apps-spout"
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

resource "google_compute_url_map" "apps" {
  name            = "${var.chain_name}-apps"
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

resource "google_compute_managed_ssl_certificate" "apps" {
  name = "${var.chain_name}-apps"

  managed {
    domains = ["explorer.${var.subdomain}", "faucet.${var.subdomain}"]
  }
}

resource "google_compute_target_http_proxy" "apps" {
  name    = "${var.chain_name}-apps-target-proxy"
  url_map = google_compute_url_map.apps.id
}

resource "google_compute_target_https_proxy" "apps" {
  name             = "${var.chain_name}-apps-target-proxy"
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
  name                  = "${var.chain_name}-otter-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.apps.id
  ip_address            = data.google_compute_global_address.explorer.address
}

resource "google_compute_global_forwarding_rule" "otter_https" {
  name                  = "${var.chain_name}-otter-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.apps.id
  ip_address            = data.google_compute_global_address.explorer.address
}

resource "google_compute_global_forwarding_rule" "faucet_http" {
  name                  = "${var.chain_name}-faucet-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.apps.id
  ip_address            = data.google_compute_global_address.faucet.address
}

resource "google_compute_global_forwarding_rule" "faucet_https" {
  name                  = "${var.chain_name}-faucet-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.apps.id
  ip_address            = data.google_compute_global_address.faucet.address
}
