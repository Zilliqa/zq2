################################################################################
# ZQ2 GCP Terraform DNS resources
################################################################################

# resource "google_dns_record_set" "this" {
#   for_each = { for idx, instance in google_compute_instance.this : idx => instance }

#   project      = var.dns_zone_project_id
#   managed_zone = local.nodes_domain_name
#   name         = each.key != "@" ? "${each.value.name}.${var.zq_network_name}.${var.nodes_dns_zone_name}." : "${var.nodes_dns_zone_name}."
#   type         = "A"
#   ttl          = try(each.value.ttl, "60")

#   rrdatas = [each.value.network_interface[0].access_config[0].nat_ip]
# }

resource "google_dns_record_set" "this" {
  for_each = { for idx, node in module.validators : idx => node }

  project      = var.dns_zone_project_id
  managed_zone = replace(var.nodes_dns_zone_name, ".", "-")
  name         = "${each.value[idx].name}.${var.network_name}.${var.nodes_dns_zone_name}."
  type         = "A"
  ttl          = "60"

  rrdatas = [each.value[idx].external_ip]
}
