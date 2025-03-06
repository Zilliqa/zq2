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

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
    condition {
      age = 7
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
    condition {
      age = 37 # 7 days in Standard + 30 days in Nearline
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
    condition {
      age = 127 # 37 days + 90 days in Coldline
    }
  }
}

resource "google_storage_bucket_iam_binding" "persistence_bucket_admins" {
  bucket = google_storage_bucket.persistence.name
  role   = "roles/storage.objectAdmin"
  members = concat([
    "serviceAccount:${module.bootstraps.service_account.email}",
    "serviceAccount:${module.validators.service_account.email}",
    "serviceAccount:${module.apis.service_account.email}",
    "serviceAccount:${module.checkpoints.service_account.email}",
    "serviceAccount:${module.persistences.service_account.email}"
    ],
    [for private_api in module.private_apis : "serviceAccount:${private_api.service_account.email}"]
  )
}
