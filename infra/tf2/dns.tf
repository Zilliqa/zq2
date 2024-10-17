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


# resource "google_compute_address" "external_regional" {
#   for_each = var.regional_subdomains

#   project = var.apps_project_id
#   region       = each.value.region
#   network_tier = local.network_tier
#   name    = each.key != "@" ? "${replace(each.key, ".", "-")}-${local.domain_name}" : local.domain_name
# }


#         bootstrap.zq2-infratest:
#           region: "asia-southeast1"