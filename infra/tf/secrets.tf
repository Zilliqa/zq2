# resource "random_bytes" "generate_node_key" {
#   count  = !var.generate_node_key ? 0 : var.vm_num
#   length = 32
# }

# resource "google_secret_manager_secret" "node_key" {
#   count     = !var.generate_node_key ? 0 : var.vm_num
#   secret_id = "${var.name}-${count.index}-${random_id.name_suffix.hex}-pk"

#   labels = merge(
#     { "zq2-network" = var.zq_network_name },
#     { "role" = var.role },
#     { "node-name" = "${var.name}-${count.index}-${random_id.name_suffix.hex}" },
#     var.labels
#   )

#   replication {
#     auto {}
#   }
# }

# resource "google_secret_manager_secret_version" "node_key_version" {
#   count       = !var.generate_node_key ? 0 : var.vm_num
#   secret      = google_secret_manager_secret.node_key[count.index].id
#   secret_data = random_bytes.generate_node_key[count.index].hex
# }




resource "random_bytes" "generate_reward_wallet" {
  for_each = merge(module.validator, module.distributed_validators)
  length = 32
}

# resource "google_secret_manager_secret" "reward_wallet" {
#   count     = !var.generate_reward_wallet ? 0 : var.vm_num
#   secret_id = "${var.name}-${count.index}-${random_id.name_suffix.hex}-wallet-pk"

#   labels = merge(
#     { "zq2-network" = var.zq_network_name },
#     { "role" = var.role },
#     { "node-name" = "${var.name}-${count.index}-${random_id.name_suffix.hex}" },
#     { "is_reward_wallet" = true },
#     var.labels
#   )

#   replication {
#     auto {}
#   }
# }

# resource "google_secret_manager_secret_version" "reward_wallet_version" {
#   count       = !var.generate_reward_wallet ? 0 : var.vm_num
#   secret      = google_secret_manager_secret.reward_wallet[count.index].id
#   secret_data = random_bytes.generate_reward_wallet[count.index].hex
# }