################################################################################
# PRIVATE API INSTANCES
################################################################################

locals {
  private_api_instances = {
    for item in flatten([
      for idx, private_api in module.private_apis : [
        for num, instance in private_api.instances_list : {
          idx         = idx
          num         = num
          zone        = instance.zone
          instance    = instance
          external_ip = instance.external_ip
        }
      ]
    ]) :
    item.instance.name => {
      idx         = item.idx
      zone        = item.zone
      instance    = item.instance
      config      = var.private_api[item.idx]
      dns_name    = var.private_api[item.idx].dns_names[item.num]
      external_ip = item.external_ip
    }
  }
}

resource "google_compute_firewall" "allow_private_api_external_http" {
  name    = "${var.chain_name}-private-api-allow-external-http"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = concat(local.google_load_balancer_ip_ranges, [local.monitoring_ip_range])

  target_tags = [format("%s-%s", var.chain_name, "private-api")]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}

module "private_apis" {
  source = "./modules/node"

  for_each = var.private_api

  config     = each.value
  chain_name = var.chain_name

  role         = "private-api"
  labels       = merge(local.labels, { "private-api" = each.key })
  network_tags = [format("%s-api-%s", var.chain_name, each.key)]

  metadata = {
    subdomain   = base64encode(var.subdomain)
    private-api = base64encode(each.key)
  }

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "private_api" {
  for_each = local.private_api_instances

  name      = each.key
  zone      = each.value.zone
  instances = [each.value.instance.self_link]

  named_port {
    name = "jsonrpc"
    port = 4201
  }

  named_port {
    name = "health"
    port = 8080
  }
}

resource "google_compute_health_check" "private_api" {
  name = "${var.chain_name}-private-api-jsonrpc"

  http_health_check {
    port               = "8080"
    port_specification = "USE_FIXED_PORT"
    request_path       = "/health"
  }
}

resource "google_compute_backend_service" "private_api" {
  for_each = local.private_api_instances

  name                  = each.key
  health_checks         = [google_compute_health_check.private_api.id]
  port_name             = "jsonrpc"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"

  dynamic "backend" {
    for_each = each.value.config.detach_load_balancer ? {} : { format("%s", each.key) = google_compute_instance_group.private_api[each.key] }
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }

  ## Attach Cloud Armor policy to the backend service
  security_policy = module.private_api_security_policies[each.key].policy.self_link
}

resource "google_compute_url_map" "private_api" {
  for_each = local.private_api_instances

  name            = each.key
  default_service = google_compute_backend_service.private_api[each.key].id

  host_rule {
    hosts        = ["${each.value.dns_name}.${var.subdomain}"]
    path_matcher = "api"
  }

  path_matcher {
    name            = "api"
    default_service = google_compute_backend_service.private_api[each.key].id

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

resource "google_compute_managed_ssl_certificate" "private_api" {
  for_each = local.private_api_instances

  name = each.key

  managed {
    domains = ["${each.value.dns_name}.${var.subdomain}"]
  }
}

resource "google_compute_target_http_proxy" "private_api" {
  for_each = local.private_api_instances

  name    = each.key
  url_map = google_compute_url_map.private_api[each.key].id
}

resource "google_compute_target_https_proxy" "private_api" {
  for_each = local.private_api_instances

  name             = each.key
  url_map          = google_compute_url_map.private_api[each.key].id
  ssl_certificates = [google_compute_managed_ssl_certificate.private_api[each.key].id]
}

data "google_compute_global_address" "private_api" {
  for_each = local.private_api_instances

  name = "${each.value.dns_name}-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "private_api_http" {
  for_each = local.private_api_instances

  name                  = "${each.key}-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.private_api[each.key].id
  ip_address            = data.google_compute_global_address.private_api[each.key].address
}

resource "google_compute_global_forwarding_rule" "private_api_https" {
  for_each = local.private_api_instances

  name                  = "${each.key}-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.private_api[each.key].id
  ip_address            = data.google_compute_global_address.private_api[each.key].address
}

module "private_api_security_policies" {
  for_each = local.private_api_instances

  source = "./modules/google-cloud-armor"

  project_id          = var.project_id
  name                = each.key
  description         = "Cloud Armor security policy for the ${each.key} public APIs"
  default_rule_action = "deny(403)"
  type                = "CLOUD_ARMOR"

  security_rules = {
    allow_whitelisted_ip_ranges = {
      action        = "allow"
      priority      = 999
      description   = "Allow whitelisted IP address ranges"
      src_ip_ranges = concat(each.value.config.firewall_source_ranges, [local.monitoring_ip_range])
    }
  }
}
