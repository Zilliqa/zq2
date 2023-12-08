terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.73.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.23.0"
    }
    kubectl = {
      source = "gavinbunney/kubectl"
      version = ">= 1.14.0"
    }
  }
}

variable "project_id" {
  type = string
  nullable = false
}

variable "eth_chain_id" {
  type = number
  nullable = false
}

variable "subdomain" {
  type = string
  nullable = false
}

provider "google" {
  project = var.project_id
  region = "europe-west2"
  zone = "europe-west2-a"
}

resource "google_storage_bucket" "binaries" {
  name                        = "${var.project_id}-zq2-binaries"
  location                    = "EUROPE-WEST2"
  uniform_bucket_level_access = true
}

locals {
  binary_location = "${path.module}/../../target/x86_64-unknown-linux-gnu/release/zilliqa"
}

resource "null_resource" "build_binary" {
  triggers = {
    always_run = "${timestamp()}"
  }

  provisioner "local-exec" {
    command = "cross build --target x86_64-unknown-linux-gnu --profile release"
    working_dir = "${path.module}/../.."
  }
}

resource "google_storage_bucket_object" "binary" {
  depends_on = [ null_resource.build_binary ]
  name   = "zq2-binary"
  source = local.binary_location
  bucket = google_storage_bucket.binaries.name
}

resource "google_compute_network" "this" {
  name                    = "zq2"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name                     = "zq2"
  ip_cidr_range            = "10.2.0.0/20"
  network                  = google_compute_network.this.name
  region                   = "europe-west2"
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "proxy_subnet" {
  name          = "zq2-proxy"
  ip_cidr_range = "10.3.0.0/20"
  network       = google_compute_network.this.name
  region        = "europe-west2"
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"
}

resource "google_compute_firewall" "allow_ingress_from_iap" {
  name    = "allow-ingress-from-iap"
  network = google_compute_network.this.name

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_internal_p2p" {
  name    = "allow-internal-p2p"
  network = google_compute_network.this.name

  direction     = "INGRESS"
  source_ranges = ["10.0.0.0/8"] # FIXME: too wide?

  allow {
    protocol = "tcp"
    ports    = ["3333"]
  }
}

resource "google_compute_firewall" "allow_external_jsonrpc" {
  name    = "allow-external-jsonrpc"
  network = google_compute_network.this.name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["4201"]
  }
}

resource "google_service_account" "node" {
  account_id = "zq2-node"
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
  byte_length = 32
}

data "external" "genesis_key_converted" {
  program = ["cargo", "run", "--bin", "convert-key"]
  working_dir = "${path.module}/../.."
  query = {
    secret_key = random_id.genesis_key.hex
  }
}

//resource "random_id" "bootstrap_key" {
//  byte_length = 32
//}

locals {
  bootstrap_key = "65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227"
}

data "external" "bootstrap_key_converted" {
  program = ["cargo", "run", "--bin", "convert-key"]
  working_dir = "${path.module}/../.."
  query = {
    secret_key = local.bootstrap_key
  }
}

locals {
  bootstrap_public_key = data.external.bootstrap_key_converted.result.public_key
  bootstrap_peer_id = data.external.bootstrap_key_converted.result.peer_id
  genesis_address = data.external.genesis_key_converted.result.address
}

module "bootstrap_node" {
  source = "./modules/node"

  name                  = "zq2-bootstrap-node"
  service_account_email = google_service_account.node.email
  network_name          = google_compute_network.this.name
  subnetwork_name       = google_compute_subnetwork.subnet.name
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
  EOT
  secret_key            = local.bootstrap_key
}

resource "random_id" "secret_key" {
  count       = 3
  byte_length = 32
}

#module "node" {
#  source = "./modules/node"
#  count = 3
#
#  name                  = "zq2-node-${count.index}"
#  service_account_email = google_service_account.node.email
#  network_name          = google_compute_network.this.name
#  subnetwork_name       = google_compute_subnetwork.subnet.name
#  binary_url            = "gs://${google_storage_bucket.binaries.name}/${google_storage_bucket_object.binary.name}"
#  binary_md5            = google_storage_bucket_object.binary.md5hash
#  config                = <<-EOT
#  p2p_port = 3333
#  bootstrap_address = [ "${local.bootstrap_peer_id}", "/ip4/${module.bootstrap_node.network_ip}/tcp/3333" ]
#
#  [[nodes]]
#  eth_chain_id = ${var.eth_chain_id}
#  allowed_timestamp_skew = { secs = 60, nanos = 0 }
#  data_dir = "/data"
#  consensus.consensus_timeout = { secs = 60, nanos = 0 }
#  consensus.genesis_committee = [ ["${local.bootstrap_public_key}", "${local.bootstrap_peer_id}"] ]
#  consensus.genesis_accounts = [ ["${local.genesis_address}", "1000000000000000000000000"] ]
#  EOT
#  secret_key = random_id.secret_key[count.index].hex
#}

resource "google_project_service" "osconfig" {
  service = "osconfig.googleapis.com"
}

resource "google_compute_instance_group" "api" {
  name      = "zq2-nodes"
  zone      = "europe-west2-a"
  instances = [module.bootstrap_node.self_link]


  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_compute_backend_service" "api" {
  name                  = "zq2-nodes"
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
  name = "zq2-jsonrpc"

  http_health_check {
    port_name          = "jsonrpc"
    port_specification = "USE_NAMED_PORT"
    request_path       = "/health"
  }
}

resource "google_compute_url_map" "api" {
  name            = "zq2"
  default_service = google_compute_backend_service.api.id
}

resource "google_compute_target_http_proxy" "api" {
  name    = "zq2-target-proxy"
  url_map = google_compute_url_map.api.id
}

resource "google_compute_target_https_proxy" "api" {
  name             = "zq2-target-proxy"
  url_map          = google_compute_url_map.api.id
  ssl_certificates = [google_compute_managed_ssl_certificate.api.id]
}

data "google_compute_global_address" "api" {
  name = "api-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "api_http" {
  depends_on = [google_compute_subnetwork.proxy_subnet]

  name                  = "zq2-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.api.id
  ip_address            = data.google_compute_global_address.api.address
}

resource "google_compute_global_forwarding_rule" "api_https" {
  depends_on = [google_compute_subnetwork.proxy_subnet]

  name                  = "zq2-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.api.id
  ip_address            = data.google_compute_global_address.api.address
}

resource "google_compute_managed_ssl_certificate" "api" {
  name = "zq2-api"

  managed {
    domains = ["api.${var.subdomain}"]
  }
}
