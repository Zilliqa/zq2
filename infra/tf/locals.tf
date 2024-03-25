################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

locals {
  binary_location      = "${path.module}/../../target/x86_64-unknown-linux-gnu/release/zilliqa"
  labels               = merge(var.labels, { "zq2-network" = var.network_name })
  bootstrap_public_key = data.external.bootstrap_key_converted.result.public_key
  bootstrap_peer_id    = data.external.bootstrap_key_converted.result.peer_id
  genesis_address      = data.external.genesis_key_converted.result.address
  network_name         = element(split("/", data.google_compute_subnetwork.default.network), length(split("/", data.google_compute_subnetwork.default.network)) - 1)
}