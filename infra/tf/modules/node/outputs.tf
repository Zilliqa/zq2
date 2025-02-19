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

output "external_ip" {
  description = "The provisioned instances network IPs"
  value       = { for instance in google_compute_instance.this : instance.name => instance.network_interface[0].access_config[0].nat_ip }
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
