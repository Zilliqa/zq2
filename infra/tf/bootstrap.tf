################################################################################
# BOOTSTRAP INSTANCES
################################################################################

module "bootstraps" {
  source = "./modules/node"

  config     = var.bootstrap
  chain_name = var.chain_name

  role         = "bootstrap"
  labels       = local.labels
  network_tags = []

  metadata = {
    subdomain = base64encode(var.subdomain)
  }

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "bootstrap" {
  for_each = toset(module.bootstraps.zones)

  name      = "${var.chain_name}-bootstrap-${each.key}"
  zone      = each.key
  instances = [for instance in module.bootstraps.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }

  named_port {
    name = "peer"
    port = "3333"
  }
}
