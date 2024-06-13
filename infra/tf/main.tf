################################################################################
# ZQ2 GCP Terraform main resources
################################################################################

resource "google_compute_firewall" "allow_ingress_from_iap" {
  name    = "${var.network_name}-allow-ingress-from-iap"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_p2p" {
  name    = "${var.network_name}-allow-p2p"
  network = local.network_name


  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["3333"]
  }
}

resource "google_compute_firewall" "allow_external_jsonrpc" {
  name    = "${var.network_name}-allow-external-jsonrpc"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["4201"]
  }
}

resource "google_service_account" "node" {
  account_id = "${var.network_name}-node"
}

data "google_project" "this" {}

resource "google_project_iam_member" "metric_writer" {
  project = data.google_project.this.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.node.email}"
}

resource "google_project_iam_member" "log_writer" {
  project = data.google_project.this.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.node.email}"
}

resource "google_project_iam_member" "artifact_registry_reader" {
  project = var.gcp_docker_registry_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.node.email}"
}

data "external" "genesis_key_converted" {
  program     = ["cargo", "run", "--bin", "convert-key"]
  working_dir = "${path.module}/../.."
  query = {
    secret_key = var.genesis_key
  }
}


data "external" "bootstrap_key_converted" {
  program     = ["cargo", "run", "--bin", "convert-key"]
  working_dir = "${path.module}/../.."
  query = {
    secret_key = var.bootstrap_key
  }
}


module "bootstrap_node" {
  source = "./modules/node"

  name                  = "${var.network_name}-bootstrap-node"
  service_account_email = google_service_account.node.email
  node_zone             = var.node_zone != "" ? var.node_zone : data.google_compute_zones.zones.names.0
  network_name          = local.network_name
  subnetwork_name       = data.google_compute_subnetwork.default.name
  docker_image          = var.docker_image
  external_ip           = data.google_compute_address.bootstrap.address
  persistence_url       = var.persistence_url
  config                = <<-EOT
  p2p_port = 3333
  [[nodes]]
  eth_chain_id = ${var.eth_chain_id}
  allowed_timestamp_skew = { secs = 60, nanos = 0 }
  data_dir = "/data"
  consensus.consensus_timeout = { secs = 60, nanos = 0 }
  consensus.genesis_accounts = [ ["${local.genesis_address}", "10_000_000_000_000_000_000_000_000"] ]
  consensus.genesis_deposits = [ ["${local.bootstrap_public_key}", "${local.bootstrap_peer_id}", "10_000_000_000_000_000_000_000_000", "${local.genesis_address}"] ]

  # Reward parameters
  consensus.rewards_per_hour = "51_000_000_000_000_000_000_000"
  consensus.blocks_per_hour = 3600
  consensus.minimum_stake = "10_000_000_000_000_000_000_000_000"
  # Gas parameters
  consensus.eth_block_gas_limit = 84000000
  consensus.gas_price = "4_761_904_800_000"
  EOT
  secret_key            = var.bootstrap_key
  zq_network_name       = var.network_name
  labels                = local.labels
}


module "node" {
  source = "./modules/node"
  count  = var.node_count

  name                  = "${var.network_name}-node-${count.index}"
  service_account_email = google_service_account.node.email
  network_name          = local.network_name
  node_zone             = var.node_zone != "" ? var.node_zone : sort(data.google_compute_zones.zones.names)[count.index % length(data.google_compute_zones.zones.names)]
  subnetwork_name       = data.google_compute_subnetwork.default.name
  docker_image          = var.docker_image
  persistence_url       = var.persistence_url

  config          = <<-EOT
  p2p_port = 3333
  bootstrap_address = [ "${local.bootstrap_peer_id}", "/ip4/${module.bootstrap_node.network_ip}/tcp/3333" ]

  [[nodes]]
  eth_chain_id = ${var.eth_chain_id}
  allowed_timestamp_skew = { secs = 60, nanos = 0 }
  data_dir = "/data"
  consensus.consensus_timeout = { secs = 60, nanos = 0 }
  consensus.genesis_accounts = [ ["${local.genesis_address}", "10_000_000_000_000_000_000_000_000"] ]
  consensus.genesis_deposits = [ ["${local.bootstrap_public_key}", "${local.bootstrap_peer_id}", "10_000_000_000_000_000_000_000_000", "${local.genesis_address}"] ]

  # Reward parameters
  consensus.rewards_per_hour = "51_000_000_000_000_000_000_000"
  consensus.blocks_per_hour = 3600
  consensus.minimum_stake = "10_000_000_000_000_000_000_000_000"
  # Gas parameters
  consensus.eth_block_gas_limit = 84000000
  consensus.gas_price = "4_761_904_800_000"
  EOT
  secret_key      = var.secret_keys[count.index]
  zq_network_name = var.network_name
}

resource "google_project_service" "osconfig" {
  service = "osconfig.googleapis.com"
}

resource "google_compute_instance_group" "ig_api_zn-a" {
  name      = "${var.network_name}-api-zone-a"
  zone      = var.node_zone != "" ? var.node_zone : data.google_compute_zones.zones.names.0
  instances = [module.bootstrap_node.self_link]


  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_compute_instance_group" "ig_api_znx" {
  count     = var.node_count
  name      = "${var.network_name}-api-zone-${sort(data.google_compute_zones.zones.names)[count.index % length(data.google_compute_zones.zones.names)]}"
  zone      = var.node_zone != "" ? var.node_zone : sort(data.google_compute_zones.zones.names)[count.index % length(data.google_compute_zones.zones.names)]
  instances = [module.node[count.index].self_link]


  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_compute_backend_service" "api" {
  name                  = "${var.network_name}-api-nodes"
  health_checks         = [google_compute_health_check.api.id]
  port_name             = "jsonrpc"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false
  session_affinity      = "CLIENT_IP"
  backend {
    group           = google_compute_instance_group.ig_api_zn-a.self_link
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
  }

  dynamic "backend" {
    for_each = google_compute_instance_group.ig_api_znx
    content {
      group           = backend.value.self_link
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
    }
  }
}

resource "google_compute_health_check" "api" {
  name = "${var.network_name}-jsonrpc"

  http_health_check {
    port_name          = "jsonrpc"
    port_specification = "USE_NAMED_PORT"
    request_path       = "/health"
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

data "google_compute_address" "bootstrap" {
  name = "bootstrap-${replace(var.subdomain, ".", "-")}"
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
