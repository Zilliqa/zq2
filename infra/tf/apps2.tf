################################################################################
# ZQ2 GCP Terraform apps resources
################################################################################

resource "google_service_account" "apps2" {
  account_id = substr("${var.network_name}-apps2", 0, 28)
}

module "apps2" {
  source = "./modules/node"
  vm_num = var.apps_node_count

  role                  = "apps"
  name                  = "${var.network_name}-apps2"
  service_account_email = google_service_account.apps2.email
  dns_zone_project_id   = var.dns_zone_project_id
  nodes_dns_zone_name   = var.nodes_dns_zone_name
  network_name          = local.network_name
  node_zones            = local.default_zones
  subnetwork_name       = data.google_compute_subnetwork.default.name
  subdomain             = var.subdomain
  generate_node_key     = false
  persistence_url       = ""
  genesis_key           = local.genesis_key
  node_type             = var.apps_node_type
  provisioning_model    = var.provisioning_model

  zq_network_name = var.network_name
}

resource "google_compute_instance_group" "apps" {
  for_each = toset(local.default_zones)

  name      = "${var.network_name}-apps2-${each.key}"
  zone      = each.key
  instances = [for instance in module.apps.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "otterscan"
    port = "80"
  }

  named_port {
    name = "spout"
    port = "8080"
  }
}
