################################################################################
# API INSTANCES
################################################################################

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

  named_port {
    name = "health"
    port = "8080"
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
  timeout_sec           = var.api.load_balancer_timeout

  dynamic "backend" {
    for_each = var.api.detach_load_balancer ? {} : google_compute_instance_group.api
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }

  ## Attach Cloud Armor policy to the backend service
  security_policy = module.api_security_policies.policy.self_link
}

resource "google_compute_backend_service" "health" {
  name                  = "${var.chain_name}-api-health-nodes"
  health_checks         = [google_compute_health_check.api.id]
  port_name             = "health"
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

  ## Attach Cloud Armor policy to the backend service
  security_policy = module.health_security_policies.policy.self_link
}

resource "google_compute_url_map" "api_http_redirect" {
  name = "${var.chain_name}-api-http-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_url_map" "api" {
  name            = format("%s-api", var.chain_name)
  default_service = google_compute_backend_service.api.id

  host_rule {
    hosts        = concat(["api.${var.subdomain}"], var.api.alternative_ssl_domains.api)
    path_matcher = "api"
  }

  host_rule {
    hosts        = concat(["health.${var.subdomain}"], var.api.alternative_ssl_domains.health)
    path_matcher = "health"
  }

  path_matcher {
    name            = "api"
    default_service = google_compute_backend_service.api.id

    default_route_action {
      cors_policy {
        allow_origins = ["*"]
        allow_methods = ["GET", "HEAD", "POST", "OPTIONS", "PUT"]
        allow_headers = ["Content-Type", "Access-Control-Allow-Origin", "x-goog-resumable"]
        max_age       = 3600
      }
    }
  }

  path_matcher {
    name            = "health"
    default_service = google_compute_backend_service.health.id

    default_route_action {
      cors_policy {
        allow_origins = ["*"]
        allow_methods = ["GET", "HEAD", "POST", "OPTIONS", "PUT"]
        allow_headers = ["Content-Type", "Access-Control-Allow-Origin", "x-goog-resumable"]
        max_age       = 3600
      }
    }
  }
}

resource "google_compute_managed_ssl_certificate" "api" {
  name = "${var.chain_name}-api"

  managed {
    domains = concat(
      ["api.${var.subdomain}", "health.${var.subdomain}"],
      var.api.alternative_ssl_domains.api,
      var.api.alternative_ssl_domains.health
    )
  }
}

resource "google_compute_target_http_proxy" "api" {
  name    = "${var.chain_name}-target-proxy"
  url_map = google_compute_url_map.api_http_redirect.id
}

resource "google_compute_target_https_proxy" "api" {
  name             = "${var.chain_name}-target-proxy"
  url_map          = google_compute_url_map.api.id
  ssl_certificates = [google_compute_managed_ssl_certificate.api.id]
}

data "google_compute_global_address" "api" {
  name = "api-${replace(var.subdomain, ".", "-")}"
}

data "google_compute_global_address" "health" {
  name = "health-${replace(var.subdomain, ".", "-")}"
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

resource "google_compute_global_forwarding_rule" "health_http" {
  name                  = "${var.chain_name}-health-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.api.id
  ip_address            = data.google_compute_global_address.health.address
}

resource "google_compute_global_forwarding_rule" "health_https" {
  name                  = "${var.chain_name}-health-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.api.id
  ip_address            = data.google_compute_global_address.health.address
}

module "api_security_policies" {
  source = "./modules/google-cloud-armor"

  project_id          = var.project_id
  name                = "${var.chain_name}-api"
  description         = "Cloud Armor security policy for the ${var.chain_name} public APIs"
  default_rule_action = "deny(403)"
  type                = "CLOUD_ARMOR"

  security_rules = merge(
    {
      whitelisted_default_ip_ranges = {
        action        = "allow"
        priority      = 999
        description   = "Allow whitelisted default IP address ranges"
        src_ip_ranges = ["*"]
      }
    },
    {
      for rule_name, rule_config in var.api.allow_ip_ranges : rule_name => merge(
        {
          action        = rule_config.action
          priority      = rule_config.priority
          description   = rule_config.description
          src_ip_ranges = rule_config.src_ip_ranges
          }, rule_config.action == "throttle" ? {
          rate_limit_options = {
            enforce_on_key                       = "IP"
            exceed_action                        = "deny(429)"
            rate_limit_http_request_count        = rule_config.rate_limit_count
            rate_limit_http_request_interval_sec = 60
          }
        } : {}
      )
    }
  )

  custom_rules = merge(
    {
      throttle = {
        action      = "throttle"
        priority    = 990
        description = "Limit requests per IP"
        expression  = "request.method == 'POST' && !inIpRange(origin.ip, '${local.monitoring_ip_range}')"
        rate_limit_options = {
          enforce_on_key                       = "IP"
          exceed_action                        = "deny(429)"
          rate_limit_http_request_count        = var.api.rate_limit
          rate_limit_http_request_interval_sec = 60
        }
      }
    },
    {
      for rule_name, rule_config in var.api.allow_api_keys : rule_name => merge(
        {
          action      = rule_config.action
          priority    = rule_config.priority
          description = rule_config.description
          expression  = "has(request.headers['rate-limit-key']) && request.headers['rate-limit-key'] == '${rule_config.api_key}'"
          }, rule_config.action == "throttle" ? {
          rate_limit_options = {
            enforce_on_key                       = "IP"
            exceed_action                        = "deny(429)"
            rate_limit_http_request_count        = rule_config.rate_limit_count
            rate_limit_http_request_interval_sec = 60
          }
      } : {})
    },
    {
      for rule_name, rule_config in var.api.allow_custom_rules : rule_name => merge(
        {
          action      = rule_config.action
          priority    = rule_config.priority
          description = rule_config.description
          expression  = rule_config.expression
          }, rule_config.action == "throttle" ? {
          rate_limit_options = {
            enforce_on_key                       = "IP"
            exceed_action                        = "deny(429)"
            rate_limit_http_request_count        = rule_config.rate_limit_count
            rate_limit_http_request_interval_sec = 60
          }
      } : {})
    }
  )
}

module "health_security_policies" {
  source = "./modules/google-cloud-armor"

  project_id          = var.project_id
  name                = "${var.chain_name}-health"
  description         = "Cloud Armor security policy for the ${var.chain_name} public health endpoint"
  default_rule_action = "deny(403)"
  type                = "CLOUD_ARMOR"

  security_rules = {
    allow_whitelisted_ip_ranges = {
      action        = "allow"
      priority      = 999
      description   = "Allow whitelisted IP address ranges"
      src_ip_ranges = [local.monitoring_ip_range]
    }
  }
}

################################################################################
# SECRET MANAGER - Rate Limit Bypass IPs and API Keys
################################################################################

# Extract all IPs from allow_ip_ranges
locals {
  bypass_ips = distinct(flatten([
    for rule_name, rule_config in var.api.allow_ip_ranges : rule_config.src_ip_ranges
  ]))

  # Extract API keys from allow_custom_rules expressions
  # Pattern: "has(request.headers['rate-limit-key']) && request.headers['rate-limit-key'] == 'HEX_STRING'"
  bypass_api_keys = distinct(flatten([
    for rule_name, rule_config in var.api.allow_api_keys : rule_config.api_key
  ]))

  # Create JSON structure for the secret
  rate_limit_bypass_data = jsonencode({
    ips      = local.bypass_ips
    api_keys = local.bypass_api_keys
  })
}

resource "google_secret_manager_secret" "rate_limit_bypass" {
  secret_id = "${var.chain_name}-rate-limit-bypass"

  replication {
    auto {}
  }

  depends_on = [google_project_service.secret_manager]
}

resource "google_secret_manager_secret_version" "rate_limit_bypass" {
  secret      = google_secret_manager_secret.rate_limit_bypass.id
  secret_data = local.rate_limit_bypass_data

  depends_on = [google_secret_manager_secret.rate_limit_bypass]
}

resource "google_secret_manager_secret_iam_binding" "rate_limit_bypass_endpoint_access" {
  secret_id = google_secret_manager_secret.rate_limit_bypass.secret_id
  role      = "roles/secretmanager.secretAccessor"

  members = concat(
    flatten([
      [for name, instance in module.bootstraps.instances : "serviceAccount:${instance.service_account}"],
      [for name, instance in module.validators.instances : "serviceAccount:${instance.service_account}"],
      [for name, instance in module.apis.instances : "serviceAccount:${instance.service_account}"],
      [for name, instance in module.opsnodes.instances : "serviceAccount:${instance.service_account}"]
    ]),
    flatten([
      for private_api in module.private_apis : [
        for name, instance in private_api.instances : "serviceAccount:${instance.service_account}"
      ]
    ])
  )

  depends_on = [google_secret_manager_secret.rate_limit_bypass]
}
