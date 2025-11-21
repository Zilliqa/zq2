################################################################################
# ZQ2 GCP Terraform apps resources
################################################################################

resource "google_compute_firewall" "allow_apps_external_http" {
  name    = "${var.chain_name}-apps-allow-external-http"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = local.google_load_balancer_ip_ranges

  target_tags = [format("%s-%s", var.chain_name, "apps")]

  allow {
    protocol = "tcp"
    ports    = ["80", "8080", "3000"]
  }
}

module "apps" {
  source = "./modules/node"

  config     = var.apps
  chain_name = var.chain_name

  role         = "apps"
  labels       = local.labels
  network_tags = []

  metadata = {
    subdomain = base64encode(var.subdomain)
  }

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

  dynamic "named_port" {
    for_each = var.apps.enable_faucet ? [1] : []
    content {
      name = "spout"
      port = "8080"
    }
  }

  named_port {
    name = "stats"
    port = "3000"
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
  count = var.apps.enable_faucet ? 1 : 0
  name  = "${var.chain_name}-spout"

  http_health_check {
    port_name          = "spout"
    port_specification = "USE_NAMED_PORT"
    request_path       = "/"
  }
}

resource "google_compute_health_check" "stats" {
  name = "${var.chain_name}-stats"

  http_health_check {
    port_name          = "stats"
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
    for_each = var.apps.detach_load_balancer ? {} : google_compute_instance_group.apps
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }
}

resource "google_compute_backend_service" "spout" {
  count                 = var.apps.enable_faucet ? 1 : 0
  name                  = "${var.chain_name}-apps-spout"
  health_checks         = [google_compute_health_check.spout[0].id]
  port_name             = "spout"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = var.apps.detach_load_balancer ? {} : google_compute_instance_group.apps
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }

  ## Attach Cloud Armor policy to the backend service
  security_policy = var.apps.enable_faucet ? module.spout_security_policies[0].policy.self_link : null
}

resource "google_compute_backend_service" "stats" {
  name                  = "${var.chain_name}-apps-stats"
  health_checks         = [google_compute_health_check.stats.id]
  port_name             = "stats"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = var.apps.detach_load_balancer ? {} : google_compute_instance_group.apps
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }
}

resource "google_compute_url_map" "apps_http_redirect" {
  name = "${var.chain_name}-apps-http-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_url_map" "apps" {
  name            = "${var.chain_name}-apps"
  default_service = google_compute_backend_service.otterscan.id

  host_rule {
    hosts        = concat(["otterscan.${var.subdomain}"], var.apps.alternative_ssl_domains.otterscan)
    path_matcher = "otterscan"
  }

  dynamic "host_rule" {
    for_each = var.apps.enable_faucet ? [1] : []
    content {
      hosts        = concat(["faucet.${var.subdomain}"], var.apps.alternative_ssl_domains.faucet)
      path_matcher = "faucet"
    }
  }

  host_rule {
    hosts        = concat(["stats.${var.subdomain}"], var.apps.alternative_ssl_domains.stats)
    path_matcher = "stats"
  }

  path_matcher {
    name            = "otterscan"
    default_service = google_compute_backend_service.otterscan.id
  }

  dynamic "path_matcher" {
    for_each = var.apps.enable_faucet ? [1] : []
    content {
      name            = "faucet"
      default_service = google_compute_backend_service.spout[0].id
    }
  }

  path_matcher {
    name            = "stats"
    default_service = google_compute_backend_service.stats.id
  }
}

resource "google_compute_managed_ssl_certificate" "apps" {
  name = "${var.chain_name}-apps"

  managed {
    domains = concat(
      ["otterscan.${var.subdomain}"],
      var.apps.enable_faucet ? ["faucet.${var.subdomain}"] : [],
      ["stats.${var.subdomain}"],
      var.apps.alternative_ssl_domains.otterscan,
      var.apps.enable_faucet ? var.apps.alternative_ssl_domains.faucet : [],
      var.apps.alternative_ssl_domains.stats
    )
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

data "google_compute_global_address" "otterscan" {
  name = "otterscan-${replace(var.subdomain, ".", "-")}"
}

data "google_compute_global_address" "faucet" {
  count = var.apps.enable_faucet ? 1 : 0
  name  = "faucet-${replace(var.subdomain, ".", "-")}"
}

data "google_compute_global_address" "stats" {
  name = "stats-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "otterscan_http" {
  name                  = "${var.chain_name}-otterscan-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.apps.id
  ip_address            = data.google_compute_global_address.otterscan.address
}

resource "google_compute_global_forwarding_rule" "otterscan_https" {
  name                  = "${var.chain_name}-otterscan-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.apps.id
  ip_address            = data.google_compute_global_address.otterscan.address
}

resource "google_compute_global_forwarding_rule" "faucet_http" {
  count                 = var.apps.enable_faucet ? 1 : 0
  name                  = "${var.chain_name}-faucet-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.apps.id
  ip_address            = data.google_compute_global_address.faucet[0].address
}

resource "google_compute_global_forwarding_rule" "faucet_https" {
  count                 = var.apps.enable_faucet ? 1 : 0
  name                  = "${var.chain_name}-faucet-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.apps.id
  ip_address            = data.google_compute_global_address.faucet[0].address
}

resource "google_compute_global_forwarding_rule" "stats_http" {
  name                  = "${var.chain_name}-stats-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.apps.id
  ip_address            = data.google_compute_global_address.stats.address
}

resource "google_compute_global_forwarding_rule" "stats_https" {
  name                  = "${var.chain_name}-stats-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.apps.id
  ip_address            = data.google_compute_global_address.stats.address
}

module "spout_security_policies" {
  count  = var.apps.enable_faucet ? 1 : 0
  source = "./modules/google-cloud-armor"

  project_id          = var.project_id
  name                = "${var.chain_name}-apps-spout"
  description         = "Cloud Armor security policy for the ${var.chain_name} faucet"
  default_rule_action = "deny(403)"
  type                = "CLOUD_ARMOR"

  security_rules = {
    allow_whitelisted_ip_ranges = {
      action        = "allow"
      priority      = 999
      description   = "Allow whitelisted IP address ranges"
      src_ip_ranges = ["*"]
    }
  }

  custom_rules = {
    throttle = {
      action      = "throttle"
      priority    = 990
      description = "Limit requests per IP"
      expression  = "!inIpRange(origin.ip, '${local.monitoring_ip_range}')"
      rate_limit_options = {
        enforce_on_key                       = "IP"
        exceed_action                        = "deny(429)"
        rate_limit_http_request_count        = var.apps.faucet_max_hourly_requests
        rate_limit_http_request_interval_sec = 3600
      }
    }
  }
}