################################################################################
# ZQ2 GCP Terraform main resources
################################################################################

resource "google_project_service" "secret_manager" {
  service            = "secretmanager.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

resource "google_project_service" "osconfig" {
  service            = "osconfig.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

resource "google_project_service" "certificate_manager" {
  service            = "certificatemanager.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

resource "google_project_service" "cloud_dns" {
  service            = "dns.googleapis.com"
  project            = var.project_id
  disable_on_destroy = false
}

################################################################################
# GENESIS KEY
################################################################################

resource "random_bytes" "generate_genesis_key" {
  length = 32
}

resource "google_secret_manager_secret" "genesis_key" {
  secret_id = "${var.chain_name}-genesis-key"

  labels = merge({ "role" = "genesis" }, local.labels)

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "genesis_key_version" {
  secret      = google_secret_manager_secret.genesis_key.id
  secret_data = random_bytes.generate_genesis_key.hex
}

################################################################################
# PERSISTENCE BUCKET
################################################################################

resource "google_storage_bucket" "persistence" {
  name     = join("-", compact([var.chain_name, "persistence"]))
  project  = var.project_id
  location = var.region
  labels   = local.labels

  force_destroy               = var.persistence_bucket_force_destroy
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"

  versioning {
    enabled = true
  }
}

################################################################################
# FIREWALL POLICIES
################################################################################

resource "google_compute_firewall" "allow_ingress_from_iap" {
  name    = "${var.chain_name}-allow-ingress-from-iap"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]

  target_tags = [var.chain_name]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_p2p" {
  name    = "${var.chain_name}-allow-p2p"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  target_tags = [var.chain_name]

  allow {
    protocol = "tcp"
    ports    = ["3333"]
  }

  allow {
    protocol = "udp"
    ports    = ["3333"]
  }
}

resource "google_compute_firewall" "allow_external_jsonrpc" {
  name    = "${var.chain_name}-allow-external-jsonrpc"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  target_tags = [var.chain_name]

  allow {
    protocol = "tcp"
    ports    = ["4201"]
  }
}

################################################################################
# BOOTSTRAP INSTANCES
################################################################################

module "bootstraps" {
  source = "./modules/node"

  config     = var.bootstrap
  chain_name = var.chain_name

  role                   = "bootstrap"
  labels                 = {}
  network_tags           = []
  generate_node_key      = true
  generate_reward_wallet = false

  metadata = {
    persistence_url = base64encode(var.persistence_url)
    subdomain       = base64encode("")
    genesis_key     = base64encode("")
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
}

################################################################################
# VALIDATOR INSTANCES
################################################################################

module "validators" {
  source = "./modules/node"

  config     = var.validator
  chain_name = var.chain_name

  role                   = "validator"
  labels                 = {}
  network_tags           = []
  generate_node_key      = true
  generate_reward_wallet = true

  metadata = {
    persistence_url = base64encode(var.persistence_url)
    subdomain       = base64encode("")
    genesis_key     = base64encode("")
  }

  node_dns_subdomain       = var.node_dns_subdomain
  node_dns_zone_project_id = var.node_dns_zone_project_id

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "validator" {
  for_each = toset(module.validators.zones)

  name      = "${var.chain_name}-validator-${each.key}"
  zone      = each.key
  instances = [for instance in module.validators.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

################################################################################
# API INSTANCES
################################################################################

module "apis" {
  source = "./modules/node"

  config     = var.api
  chain_name = var.chain_name

  role                   = "api"
  labels                 = {}
  network_tags           = []
  generate_node_key      = true
  generate_reward_wallet = false

  metadata = {
    persistence_url = base64encode(var.persistence_url)
    subdomain       = base64encode("")
    genesis_key     = base64encode("")
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
  source_ranges = local.google_load_balancer_ip_ranges

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
    for_each = google_compute_instance_group.api
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
