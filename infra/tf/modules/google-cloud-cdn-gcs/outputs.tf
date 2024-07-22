####################
# Outputs
####################
output "cdn_external_ip" {
  value = google_compute_global_address.default.address
}

output "cdn_name" {
  value = var.dns_name
}