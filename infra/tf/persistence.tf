################################################################################
# ZQ2 GCP Terraform persistence resources
################################################################################

module "persistences" {
  source = "./modules/node"

  config     = var.persistence
  chain_name = var.chain_name

  role         = "persistence"
  labels       = local.labels
  network_tags = []

  metadata = {
    subdomain = base64encode("")
  }

  node_dns_subdomain       = var.node_dns_subdomain
  node_dns_zone_project_id = var.node_dns_zone_project_id

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "persistence" {
  for_each = toset(module.persistences.zones)

  name      = "${var.chain_name}-persistence-${each.key}"
  zone      = each.key
  instances = [for instance in module.persistences.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_compute_firewall" "allow_persistence_external_http" {
  name    = "${var.chain_name}-persistence-allow-external-http"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = [local.monitoring_ip_range]

  target_tags = [format("%s-%s", var.chain_name, "persistence")]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }
}
