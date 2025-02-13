################################################################################
# PRIVATE API INSTANCES
################################################################################

resource "google_compute_firewall" "allow_private_api_external_jsonrpc" {
  for_each = var.private_api

  name    = format("%s-allow-api-%s-external-jsonrpc", var.chain_name, each.key)
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = concat([local.iap_ip_range], each.value.firewall_source_ranges)
  priority      = 990

  target_tags = [format("%s-api-%s", var.chain_name, each.key)]

  allow {
    protocol = "tcp"
    ports    = ["4201"]
  }
}

resource "google_compute_firewall" "deny_private_api_external_jsonrpc" {
  for_each = var.private_api

  name    = format("%s-deny-api-%s-external-jsonrpc", var.chain_name, each.key)
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  target_tags = [format("%s-api-%s", var.chain_name, each.key)]

  deny {
    protocol = "tcp"
    ports    = ["4201"]
  }
}

module "private_apis" {
  source = "./modules/node"

  for_each = var.private_api

  config     = each.value
  chain_name = var.chain_name

  role         = "private-api"
  labels       = merge(local.labels, { "private-api" = each.key })
  network_tags = [format("%s-api-%s", var.chain_name, each.key)]

  metadata = {
    subdomain   = base64encode(var.subdomain)
    private-api = base64encode(each.key)
  }

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "private_api" {
  # Flatten the zones across all modules into a single map
  for_each = {
    for item in flatten([
      for idx, private_api in module.private_apis : [
        for zone in private_api.zones : {
          idx       = idx
          zone      = zone
          instances = [for instance in private_api.instances : instance.self_link if instance.zone == zone]
        }
      ]
    ]) :
    "${item.idx}-${item.zone}" => {
      idx       = item.idx
      zone      = item.zone
      instances = item.instances
    }
  }

  name      = "${var.chain_name}-private-api-${each.value.idx}-${each.value.zone}"
  zone      = each.value.zone
  instances = each.value.instances

  named_port {
    name = "jsonrpc"
    port = 4201
  }

  named_port {
    name = "health"
    port = 8080
  }
}
