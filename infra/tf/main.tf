terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "4.73.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.5.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.23.0"
    }
  }

  backend "gcs" {
    bucket = "bkt-prj-d-playground-b7i4vh7s-state"
    prefix = "terraform/zq2"
  }
}

provider "google" {
  project = "prj-d-playground-b7i4vh7s"
  region  = "europe-west2"
  zone    = "europe-west2-a"
}

resource "google_storage_bucket" "binaries" {
  name                        = "zq2-binaries"
  location                    = "EUROPE-WEST2"
  uniform_bucket_level_access = true
}

locals {
  binary_location = "${path.module}/../../target/x86_64-unknown-linux-gnu/release-stripped/zilliqa"
}

resource "google_storage_bucket_object" "binary" {
  name   = "zq2-binary-${filesha256(local.binary_location)}"
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

module "bootstrap_node" {
  source = "./modules/node"

  name                  = "zq2-bootstrap-node"
  service_account_email = google_service_account.node.email
  network_name          = google_compute_network.this.name
  subnetwork_name       = google_compute_subnetwork.subnet.name
  binary_url            = "gs://${google_storage_bucket.binaries.name}/${google_storage_bucket_object.binary.name}"
  config                = <<-EOT
  p2p_port = 3333

  [[nodes]]
  eth_chain_id = 33469
  allowed_timestamp_skew = { secs = 60, nanos = 0 }
  consensus_timeout = { secs = 60, nanos = 0 }
  genesis_committee = [ ["b27aebb3b54effd7af87c4a064a711554ee0f3f5abf56ca910b46422f2b21603bc383d42eb3b927c4c3b0b8381ca30a3", "12D3KooWESMZ2ttSxDwjfnNe23sHCqsJf6sNEKwgHkdgtCHDsbWU"] ]
  EOT
  secret_key            = "65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227"
}

module "node" {
  source = "./modules/node"
  count  = 3

  name                  = "zq2-node-${count.index}"
  service_account_email = google_service_account.node.email
  network_name          = google_compute_network.this.name
  subnetwork_name       = google_compute_subnetwork.subnet.name
  binary_url            = "gs://${google_storage_bucket.binaries.name}/${google_storage_bucket_object.binary.name}"
  config                = <<-EOT
  p2p_port = 3333
  bootstrap_address = [ "12D3KooWESMZ2ttSxDwjfnNe23sHCqsJf6sNEKwgHkdgtCHDsbWU", "/ip4/${module.bootstrap_node.network_ip}/tcp/3333" ]

  [[nodes]]
  eth_chain_id = 33469
  allowed_timestamp_skew = { secs = 60, nanos = 0 } 
  consensus_timeout = { secs = 60, nanos = 0 }
  genesis_committee = [ ["b27aebb3b54effd7af87c4a064a711554ee0f3f5abf56ca910b46422f2b21603bc383d42eb3b927c4c3b0b8381ca30a3", "12D3KooWESMZ2ttSxDwjfnNe23sHCqsJf6sNEKwgHkdgtCHDsbWU"] ]
  EOT
}

module "agent_policy" {
  source  = "terraform-google-modules/cloud-operations/google//modules/agent-policy"
  version = "0.3.0"

  project_id = data.google_project.this.project_id
  policy_id  = "ops-agents-zq2"
  agent_rules = [
    {
      type               = "ops-agent"
      version            = "current-major"
      package_state      = "installed"
      enable_autoupgrade = true
    },
  ]
  os_types = [
    {
      short_name = "debian"
      version    = "11"
    }
  ]
  instances = concat(
    [module.bootstrap_node.id],
    [for n in module.node : n.id],
  )
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
    group           = google_compute_instance_group.api.id
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

data "google_compute_global_address" "devnet_api" {
  name = "api-zq2-devnet-zilstg-dev"
}

resource "google_compute_global_forwarding_rule" "api_http" {
  depends_on = [google_compute_subnetwork.proxy_subnet]

  name                  = "zq2-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.api.id
  ip_address            = data.google_compute_global_address.devnet_api.address
}

resource "google_compute_global_forwarding_rule" "api_https" {
  depends_on = [google_compute_subnetwork.proxy_subnet]

  name                  = "zq2-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.api.id
  ip_address            = data.google_compute_global_address.devnet_api.address
}

resource "google_compute_managed_ssl_certificate" "api" {
  name = "zq2-devnet"

  managed {
    domains = ["api.zq2-devnet.zilstg.dev"]
  }
}
