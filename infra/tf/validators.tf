################################################################################
# ZQ2 GCP Terraform multi-region / zones validators
################################################################################

resource "google_service_account" "validators" {
  count      = length(var.distributed_validators) >= 1 ? 1 : 0
  account_id = "${var.network_name}-validators"
}

resource "google_project_iam_member" "validators_metric_writer" {
  count   = length(var.distributed_validators) >= 1 ? 1 : 0
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.validators.0.email}"
}

resource "google_project_iam_member" "validators_log_writer" {
  count   = length(var.distributed_validators) >= 1 ? 1 : 0
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.validators.0.email}"
}

resource "google_project_iam_member" "validators_artifact_registry_reader" {
  count   = length(var.distributed_validators) >= 1 ? 1 : 0
  project = var.gcp_docker_registry_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.validators.0.email}"
}

data "google_compute_zones" "validators_zones" {
  for_each = { for idx, val in var.distributed_validators : idx => val }
  project  = var.project_id
  region   = each.value.region
}


module "validators" {
  for_each = { for idx, val in var.distributed_validators : idx => val }
  source   = "./modules/node"

  name                  = "${var.network_name}-node-${each.key}"
  service_account_email = google_service_account.validators.0.email
  network_name          = local.network_name
  node_zone             = each.value.vm_zone != "" ? each.value.vm_zone : sort(data.google_compute_zones.zones.names)[each.key % length(data.google_compute_zones.zones.names)]
  subnetwork_name       = each.value.vpc_subnet_name
  docker_image          = var.docker_image
  persistence_url       = var.persistence_url
  role                  = "validator"

  config          = <<-EOT
  p2p_port = 3333
  bootstrap_address = [ "${local.bootstrap_peer_id}", "/ipv4/${data.google_compute_address.bootstrap.address}/tcp/3333" ]

  [[nodes]]
  eth_chain_id = ${var.eth_chain_id}
  allowed_timestamp_skew = { secs = 60, nanos = 0 }
  data_dir = "/data"
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
  secret_key      = each.value.node_keys[each.key]
  zq_network_name = var.network_name
}
