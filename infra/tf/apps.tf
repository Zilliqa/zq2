## Ancilliary applications for ZQ2 networks are deployed to a GKE cluster.

resource "google_compute_network" "zq2_apps" {
  name                    = "${var.network_name}-apps"
  auto_create_subnetworks = false
  count                   = local.devnet_resources

}

resource "google_compute_subnetwork" "zq2_apps" {
  name                     = "${var.network_name}-apps"
  ip_cidr_range            = "10.10.0.0/24"
  network                  = local.devnet_resources != 0 ? google_compute_network.zq2_apps.0.name : local.network_name
  region                   = var.region
  private_ip_google_access = true
  count                    = local.devnet_resources

}

resource "google_service_account" "zq2_apps" {
  account_id = "${var.network_name}-apps"
}

resource "google_container_cluster" "zq2_apps" {
  name     = "${var.network_name}-apps"
  location = var.region

  network    = local.devnet_resources != 0 ? google_compute_network.zq2_apps.0.name : local.network_name
  subnetwork = local.devnet_resources != 0 ? google_compute_subnetwork.zq2_apps.0.name : data.google_compute_subnetwork.default.name

  enable_autopilot = true

  cluster_autoscaling {
    auto_provisioning_defaults {
      service_account = google_service_account.zq2_apps.email
    }
  }

  dns_config {
    cluster_dns        = "CLOUD_DNS"
    cluster_dns_domain = "cluster.local"
    cluster_dns_scope  = "CLUSTER_SCOPE"
  }

  private_cluster_config {
    enable_private_nodes = true
  }
}

resource "google_compute_router" "router" {
  name    = "${var.network_name}-apps-router"
  network = google_compute_network.zq2_apps.0.name
  count   = local.devnet_resources

}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.network_name}-apps-nat"
  router                             = google_compute_router.router.0.name
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  region                             = var.region
  count                              = local.devnet_resources
}

data "google_client_config" "default" {}

provider "kubernetes" {
  host  = "https://${google_container_cluster.zq2_apps.endpoint}"
  token = data.google_client_config.default.access_token

  cluster_ca_certificate = base64decode(google_container_cluster.zq2_apps.master_auth.0.cluster_ca_certificate)

  ignore_annotations = [
    "^autopilot\\.gke\\.io\\/.*",
    "cloud.google.com/neg-status",
  ]
}

provider "kubectl" {
  host  = "https://${google_container_cluster.zq2_apps.endpoint}"
  token = data.google_client_config.default.access_token

  cluster_ca_certificate = base64decode(google_container_cluster.zq2_apps.master_auth.0.cluster_ca_certificate)
  load_config_file       = false
}

module "otterscan" {
  source = "./modules/app"

  name  = "otterscan"
  image = "zilliqa/otterscan:develop"
  env = [
    ["ERIGON_URL", "https://api.${var.subdomain}"],
  ]
  static_ip_name = "explorer-${replace(var.subdomain, ".", "-")}"
  domain         = "explorer.${var.subdomain}"
}

module "faucet" {
  source = "./modules/app"

  name  = "faucet"
  image = "asia-docker.pkg.dev/prj-p-devops-services-tvwmrf63/zilliqa/eth-spout:89eb40d3"
  env = [
    ["RPC_URL", "https://api.${var.subdomain}"],
    ["NATIVE_TOKEN_SYMBOL", "ZIL"],
    ["PRIVATE_KEY", local.genesis_key],
    ["ETH_AMOUNT", "100"],
    ["EXPLORER_URL", "https://explorer.${var.subdomain}"],
    ["MINIMUM_SECONDS_BETWEEN_REQUESTS", "60"],
    ["BECH32_HRP", "zil"],
  ]
  static_ip_name = "faucet-${replace(var.subdomain, ".", "-")}"
  domain         = "faucet.${var.subdomain}"
}
