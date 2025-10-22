################################################################################
# ZQ2 resources to manage the Redis instances
################################################################################

# ----------------------------
# 1. Reserve an IP range for Google-managed services
# ----------------------------
resource "google_compute_global_address" "private_service_range" {
  name          = "${var.chain_name}-google-managed-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = local.network_name
}

# ----------------------------
# 2. Create the private service connection
# ----------------------------
resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = local.network_name
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_service_range.name]
}

module "redis" {
  count = var.enable_redis ? 1 : 0

  source = "git::https://github.com/terraform-google-modules/terraform-google-memorystore.git?ref=v15.2.1"

  project_id         = var.project_id
  memory_size_gb     = 1
  enable_apis        = "true"
  auth_enabled       = "true"
  name               = "${var.chain_name}-redis"
  region             = var.region
  authorized_network = local.network_name
  connect_mode       = "PRIVATE_SERVICE_ACCESS"
  persistence_config = {
    persistence_mode = "RDB"
    rdb_snapshot_period = "ONE_HOUR"
  }
}
