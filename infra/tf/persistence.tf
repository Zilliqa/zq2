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
    subdomain = base64encode(var.subdomain)
  }

  service_account_iam = local.default_service_account_iam
  
  snapshot_schedule_policy_name = google_compute_resource_policy.persistence_snapshots_schedule.name
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

################################################################################
# PERSISTENCE BUCKET
################################################################################

resource "google_storage_bucket" "persistence" {
  name     = join("-", compact([var.chain_name, "persistence"]))
  project  = var.project_id
  location = var.region
  labels   = local.labels

  force_destroy               = var.persistence_bucket_force_destroy
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"

  versioning {
    enabled = var.persistence_bucket_versioning
  }

  # Delete noncurrent (deleted) file versions after 7 days
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      days_since_noncurrent_time = 7
      send_age_if_zero           = false
    }
  }
}

resource "google_storage_bucket_iam_binding" "persistence_bucket_admins" {
  bucket = google_storage_bucket.persistence.name
  role   = "roles/storage.objectAdmin"
  members = concat(
    flatten([
      [for name, instance in module.bootstraps.instances : "serviceAccount:${instance.service_account}"],
      [for name, instance in module.validators.instances : "serviceAccount:${instance.service_account}"],
      [for name, instance in module.apis.instances : "serviceAccount:${instance.service_account}"],
      [for name, instance in module.checkpoints.instances : "serviceAccount:${instance.service_account}"],
      [for name, instance in module.persistences.instances : "serviceAccount:${instance.service_account}"]
    ]),
    flatten([
      for private_api in module.private_apis : [
        for name, instance in private_api.instances : "serviceAccount:${instance.service_account}"
      ]
    ])
  )
}

################################################################################
# PERSISTENCE SNAPSHOTS SCHEDULE
################################################################################

resource "google_compute_resource_policy" "persistence_snapshots_schedule" {
  name   = "${var.chain_name}-persistence-snapshots-schedule"
  region = var.region
  description = "${var.chain_name} - Persistence snapshots schedule"

  snapshot_schedule_policy {
    schedule {
      hourly_schedule {
        hours_in_cycle = 1
        start_time    = "03:00"
      }
    }

    retention_policy {
      max_retention_days = 7
      on_source_disk_delete = "APPLY_RETENTION_POLICY"
    }

    snapshot_properties {
      guest_flush = false
      storage_locations = [var.region]
      chain_name = var.chain_name
      labels = local.labels
    }
  }
}
