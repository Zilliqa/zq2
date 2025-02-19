################################################################################
# VALIDATOR INSTANCES
################################################################################

module "validators" {
  source = "./modules/node"

  config     = var.validator
  chain_name = var.chain_name

  role         = "validator"
  labels       = local.labels
  network_tags = []

  metadata = {
    subdomain = base64encode(var.subdomain)
  }

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "validator" {
  for_each = toset(module.validators.zones)

  name      = "${var.chain_name}-validator-${each.key}"
  zone      = each.key
  instances = [for instance in module.validators.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}
