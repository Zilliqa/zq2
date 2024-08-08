################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

locals {
  # binary_location      = "${path.module}/../../target/x86_64-unknown-linux-gnu/release/zilliqa"
  # bootstrap_public_key = data.external.bootstrap_key_converted.result.bls_public_key
  # bootstrap_peer_id    = data.external.bootstrap_key_converted.result.peer_id
  # genesis_address      = data.external.genesis_key_converted.result.address
  default_zones = var.node_zone != "" ? [var.node_zone] : sort(data.google_compute_zones.zones.names)
  labels        = merge(var.labels, { "zq2-network" = var.network_name })
  network_name  = element(split("/", data.google_compute_subnetwork.default.network), length(split("/", data.google_compute_subnetwork.default.network)) - 1)
  genesis_key   = google_secret_manager_secret_version.genesis_key_version.secret_data
}
