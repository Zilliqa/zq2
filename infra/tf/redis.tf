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

  project_id              = var.project_id
  memory_size_gb          = 1
  enable_apis             = "true"
  auth_enabled            = "true"
  name                    = "${var.chain_name}-redis"
  region                  = var.region
  authorized_network      = local.network_name
  connect_mode            = "PRIVATE_SERVICE_ACCESS"
  transit_encryption_mode = "DISABLED"
  persistence_config = {
    persistence_mode    = "RDB"
    rdb_snapshot_period = "ONE_HOUR"
  }
}

# ----------------------------
# 3. Create Secret Manager secret for Redis endpoint
# ----------------------------
resource "google_secret_manager_secret" "redis_endpoint" {
  count = var.enable_redis ? 1 : 0

  secret_id = "${var.chain_name}-redis-endpoint"

  replication {
    auto {}
  }

  depends_on = [module.redis]
}

resource "google_secret_manager_secret_version" "redis_endpoint" {
  count = var.enable_redis ? 1 : 0

  secret      = google_secret_manager_secret.redis_endpoint[0].id
  secret_data = "redis://:${module.redis[0].auth_string}@${module.redis[0].host}:${module.redis[0].port}/?ssl_cert_reqs=none"

  depends_on = [google_secret_manager_secret.redis_endpoint]
}

# ----------------------------
# 4. Grant access to Redis secret for all service accounts
# ----------------------------
resource "google_secret_manager_secret_iam_binding" "redis_endpoint_access" {
  count = var.enable_redis ? 1 : 0

  secret_id = google_secret_manager_secret.redis_endpoint[0].secret_id
  role      = "roles/secretmanager.secretAccessor"

  members = concat(
    flatten([
      [for name, instance in module.bootstraps.instances : "serviceAccount:${instance.service_account}"],
      [for name, instance in module.validators.instances : "serviceAccount:${instance.service_account}"],
      [for name, instance in module.apis.instances : "serviceAccount:${instance.service_account}"],
      [for name, instance in module.opsnodes.instances : "serviceAccount:${instance.service_account}"]
    ]),
    flatten([
      for private_api in module.private_apis : [
        for name, instance in private_api.instances : "serviceAccount:${instance.service_account}"
      ]
    ])
  )

  depends_on = [google_secret_manager_secret.redis_endpoint]
}
