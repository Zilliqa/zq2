output "instances" {
  description = "The provisioned instances"
  value = {
    for instance in google_compute_instance.this : instance.name => {
      name        = instance.name,
      external_ip = instance.network_interface[0].access_config[0].nat_ip,
      zone        = instance.zone,
      self_link   = instance.self_link,
    }
  }
}

output "id" {
  description = "The provisioned instances IDs"
  value       = { for instance in google_compute_instance.this : instance.name => instance.id }
}

output "self_link" {
  description = "The provisioned instances self link"
  value       = { for instance in google_compute_instance.this : instance.name => instance.self_link }
}

output "network_ip" {
  description = "The provisioned instances network IPs"
  value       = { for instance in google_compute_instance.this : instance.name => instance.network_interface[0].network_ip }
}

output "node_key" {
  description = "The secret ID of the node private key in GCP Secrets Manager"
  value       = [for secret in google_secret_manager_secret_version.node_key_version : secret.id]
}

output "reward_wallet" {
  description = "The secret ID of the node private key in GCP Secrets Manager"
  value       = [for secret in google_secret_manager_secret_version.reward_wallet_version : secret.id]
}

output "zones" {
  description = "The GCP zones where the instances are deployed in"
  value = distinct(flatten([
    for instance in local.instances : instance.zone
  ]))
}

output "service_account" {
  description = "The GCP service account associated to the instances"
  value       = google_service_account.this
}
