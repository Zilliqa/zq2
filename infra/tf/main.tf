################################################################################
# ZQ2 GCP Terraform main resources
################################################################################

resource "google_storage_bucket" "binaries" {
  name                        = "${var.project_id}-${var.network_name}-binaries"
  location                    = upper(var.region)
  uniform_bucket_level_access = true
}

resource "null_resource" "build_binary" {
  triggers = {
    always_run = "${timestamp()}"
  }

  provisioner "local-exec" {
    command     = "cross build --target x86_64-unknown-linux-gnu --profile release"
    working_dir = "${path.module}/../.."
  }
}

resource "google_storage_bucket_object" "binary" {
  depends_on = [null_resource.build_binary]
  name       = "${var.network_name}-binary"
  source     = local.binary_location
  bucket     = google_storage_bucket.binaries.name
}

resource "google_compute_network" "this" {
  name                    = var.network_name
  auto_create_subnetworks = false
  count                   = local.devnet_resources
}

resource "google_compute_subnetwork" "subnet" {
  name                     = var.network_name
  ip_cidr_range            = var.subnet_cidr
  network                  = google_compute_network.this.0.name
  region                   = var.region
  private_ip_google_access = true
  count                    = local.devnet_resources
}

resource "google_compute_subnetwork" "proxy_subnet" {
  name          = "${var.network_name}-proxy"
  ip_cidr_range = var.proxy_subnet_cidr
  network       = google_compute_network.this.0.name
  region        = var.region
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
  count         = local.devnet_resources
}

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

resource "google_compute_firewall" "allow_internal_p2p" {
  name    = "${var.network_name}-allow-internal-p2p"
  network = local.network_name


  direction     = "INGRESS"
  source_ranges = [data.google_compute_subnetwork.default.ip_cidr_range]

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

resource "google_storage_bucket_iam_member" "this" {
  bucket = google_storage_bucket.binaries.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.node.email}"
}

resource "random_id" "genesis_key" {
  count       = local.devnet_resources
  byte_length = 32
}

data "external" "genesis_key_converted" {
  program     = ["cargo", "run", "--bin", "convert-key"]
  working_dir = "${path.module}/../.."
  query = {
    secret_key = local.genesis_key
  }
}

resource "random_id" "bootstrap_key" {
  count       = local.devnet_resources
  byte_length = 32
}

data "external" "bootstrap_key_converted" {
  program     = ["cargo", "run", "--bin", "convert-key"]
  working_dir = "${path.module}/../.."
  query = {
    secret_key = local.bootstrap_key
  }
}

locals {

}

module "bootstrap_node" {
  source = "./modules/node"

  name                  = "${var.network_name}-bootstrap-node"
  service_account_email = google_service_account.node.email
  network_name          = local.network_name
  subnetwork_name       = data.google_compute_subnetwork.default.name
  binary_url            = "gs://${google_storage_bucket.binaries.name}/${google_storage_bucket_object.binary.name}"
  binary_md5            = google_storage_bucket_object.binary.md5hash
  config                = <<-EOT
  p2p_port = 3333

  [[nodes]]
  eth_chain_id = ${var.eth_chain_id}
  allowed_timestamp_skew = { secs = 60, nanos = 0 }
  data_dir = "/data"
  consensus.consensus_timeout = { secs = 60, nanos = 0 }
  consensus.genesis_committee = [ ["${local.bootstrap_public_key}", "${local.bootstrap_peer_id}"] ]
  consensus.genesis_accounts = [ ["${local.genesis_address}", "1000000000000000000000000"] ]
  consensus.genesis_deposits = [ ["${local.bootstrap_public_key}", "32000000000000000000", "${local.genesis_address}"] ]

  EOT
  secret_key            = local.bootstrap_key
  zq_network_name       = var.network_name
  labels                = local.labels
}

resource "random_id" "secret_key" {
  count       = local.devnet_resources == 1 ? var.node_count : 0
  byte_length = 32
}

module "node" {
  source = "./modules/node"
  count  = var.node_count

  name                  = "${var.network_name}-node-${count.index}"
  service_account_email = google_service_account.node.email
  network_name          = local.network_name
  node_zone             = var.node_zone
  subnetwork_name       = data.google_compute_subnetwork.default.name
  binary_url            = "gs://${google_storage_bucket.binaries.name}/${google_storage_bucket_object.binary.name}"
  binary_md5            = google_storage_bucket_object.binary.md5hash
  config                = <<-EOT
  p2p_port = 3333
  bootstrap_address = [ "${local.bootstrap_peer_id}", "/ip4/${module.bootstrap_node.network_ip}/tcp/3333" ]

  [[nodes]]
  eth_chain_id = ${var.eth_chain_id}
  allowed_timestamp_skew = { secs = 60, nanos = 0 }
  data_dir = "/data"
  consensus.consensus_timeout = { secs = 60, nanos = 0 }
  consensus.genesis_committee = [ ["${local.bootstrap_public_key}", "${local.bootstrap_peer_id}"] ]
  consensus.genesis_accounts = [ ["${local.genesis_address}", "1000000000000000000000000"] ]
  consensus.genesis_deposits = [ ["${local.bootstrap_public_key}", "32000000000000000000", "${local.genesis_address}"] ]

  EOT
  secret_key            = local.secret_keys[count.index]
  zq_network_name       = var.network_name
}

resource "google_project_service" "osconfig" {
  service = "osconfig.googleapis.com"
}

resource "google_compute_instance_group" "api" {
  name      = "${var.network_name}-nodes"
  zone      = "${var.region}-a"
  instances = [module.bootstrap_node.self_link]


  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_compute_backend_service" "api" {
  name                  = "${var.network_name}-nodes"
  health_checks         = [google_compute_health_check.api.id]
  port_name             = "jsonrpc"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  enable_cdn            = false

  backend {
    group           = google_compute_instance_group.api.self_link
    balancing_mode  = "UTILIZATION"
    capacity_scaler = 1.0
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

resource "google_compute_global_forwarding_rule" "api_http" {
  depends_on = [google_compute_subnetwork.proxy_subnet]

  name                  = "${var.network_name}-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.api.id
  ip_address            = data.google_compute_global_address.api.address
}

resource "google_compute_global_forwarding_rule" "api_https" {
  depends_on = [google_compute_subnetwork.proxy_subnet]

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
