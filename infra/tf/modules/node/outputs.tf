output "instances" {
  description = "The instances"
  value       = google_compute_instance.this[*]
}

output "id" {
  description = "The instances IDs"
  value       = google_compute_instance.this[*].id
}

output "self_link" {
  description = "The instances self link"
  value       = google_compute_instance.this[*].self_link
}

output "network_ip" {
  description = "The network IPs"
  value       = google_compute_instance.this[*].network_interface[0].network_ip
}

output "node_key" {
  description = "The secret ID of the node private key in GCP Secrets Manager"
  value       = google_secret_manager_secret_version.node_key_version[*].id
}

output "reward_wallet" {
  description = "The secret ID of the node private key in GCP Secrets Manager"
  value       = google_secret_manager_secret_version.reward_wallet_version[*].id
}
