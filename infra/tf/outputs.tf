################################################################################
# ZQ2 GCP Terraform outputs
################################################################################

# Output the secret version (useful for referencing the stored key)
output "genesis_key" {
  description = "The ID of the genesis key in GCP Secrets Manager"
  value       = google_secret_manager_secret_version.genesis_key_version.id
}

output "node_keys" {
  description = "The secret ID of the node private key in GCP Secrets Manager"
  value = flatten(concat(
    module.bootstrap_node.node_key,
    module.apis.node_key,
    module.validators.node_key,
    module.checkpoints.node_key,
  [for k, m in module.distributed_validators : m.node_key]))
}

output "reward_wallets" {
  description = "The secret ID of the node reward wallet in GCP Secrets Manager"
  value = flatten(concat(
    module.validators.reward_wallet,
  [for k, m in module.distributed_validators : m.reward_wallet]))
}
