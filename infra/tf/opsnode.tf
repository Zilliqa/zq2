################################################################################
# ZQ2 GCP Terraform opsnode resources (checkpoint + persistence combined)
################################################################################

module "opsnodes" {
  source = "./modules/node"

  config     = var.opsnode
  chain_name = var.chain_name

  role         = "opsnode"
  labels       = local.labels
  network_tags = []

  metadata = {
    subdomain = base64encode(var.subdomain)
  }

  service_account_iam = local.default_service_account_iam

  snapshot_schedule_policy_name = google_compute_resource_policy.opsnode_snapshots_schedule.name
}

resource "google_compute_instance_group" "opsnode" {
  for_each = toset(module.opsnodes.zones)

  name      = "${var.chain_name}-opsnode-${each.key}"
  zone      = each.key
  instances = [for instance in module.opsnodes.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

################################################################################
# CHECKPOINT BUCKET + CDN
################################################################################

resource "google_storage_bucket" "checkpoint" {
  name     = join("-", compact([var.chain_name, "checkpoint"]))
  project  = var.project_id
  location = var.region
  labels   = local.labels

  force_destroy               = var.opsnode.bucket_force_destroy
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"

  versioning {
    enabled = var.opsnode.bucket_versioning
  }

  # Delete objects 30 days after creation
  lifecycle_rule {
    action {
      type = "Delete"
    }
    condition {
      age            = 30
      matches_prefix = ["previous/"]
    }
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

  cors {
    origin          = ["*"]
    method          = ["GET", "HEAD", "POST", "OPTIONS", "PUT"]
    response_header = ["Content-Type", "Access-Control-Allow-Origin", "x-goog-resumable"]
    max_age_seconds = 3600
  }
}

resource "google_storage_bucket_iam_binding" "checkpoint_bucket_admins" {
  bucket = google_storage_bucket.checkpoint.name
  role   = "roles/storage.objectAdmin"
  members = [
    for name, instance in module.opsnodes.instances :
    "serviceAccount:${instance.service_account}"
  ]
}

resource "google_storage_bucket_iam_binding" "checkpoint_bucket_viewers" {
  bucket  = google_storage_bucket.checkpoint.name
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}

# backend bucket with CDN policy with default ttl settings
resource "google_compute_backend_bucket" "checkpoint" {
  name        = format("cdn-%s-backend", var.chain_name)
  bucket_name = google_storage_bucket.checkpoint.name
  enable_cdn  = true
  cdn_policy {
    cache_mode        = "CACHE_ALL_STATIC"
    client_ttl        = 0
    default_ttl       = 3600
    max_ttl           = 86400
    negative_caching  = true
    serve_while_stale = 86400
    bypass_cache_on_request_headers {
      header_name = "X-z-cdn-bypass"
    }
  }
  project = var.project_id
}

resource "google_compute_url_map" "checkpoint_http_redirect" {
  name = "${var.chain_name}-checkpoint-http-redirect"

  default_url_redirect {
    https_redirect         = true
    redirect_response_code = "MOVED_PERMANENTLY_DEFAULT"
    strip_query            = false
  }
}

resource "google_compute_url_map" "checkpoint" {
  name            = format("%s-checkpoint-cdn", var.chain_name)
  default_service = google_compute_backend_bucket.checkpoint.id
}

resource "google_compute_managed_ssl_certificate" "checkpoint" {
  name = format("%s-checkpoint-cdn", var.chain_name)

  managed {
    domains = concat(
      [format("checkpoints.%s", var.subdomain)],
      var.opsnode.alternative_ssl_domains.default
    )
  }
}

resource "google_compute_ssl_policy" "tls12_modern" {
  project         = var.project_id
  name            = format("%s-checkpoint-cdn", var.chain_name)
  profile         = "COMPATIBLE"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_target_http_proxy" "checkpoint" {
  name    = format("%s-checkpoint-cdn", var.chain_name)
  url_map = google_compute_url_map.checkpoint_http_redirect.id
}

resource "google_compute_target_https_proxy" "checkpoint" {
  name             = format("%s-checkpoint-cdn", var.chain_name)
  url_map          = google_compute_url_map.checkpoint.id
  ssl_certificates = [google_compute_managed_ssl_certificate.checkpoint.id]
  ssl_policy       = google_compute_ssl_policy.tls12_modern.id
}

data "google_compute_global_address" "checkpoint" {
  name = "checkpoints-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "checkpoint_http" {
  name                  = "${var.chain_name}-checkpoint-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.checkpoint.id
  ip_address            = data.google_compute_global_address.checkpoint.address
}

resource "google_compute_global_forwarding_rule" "checkpoint_https" {
  name                  = "${var.chain_name}-checkpoint-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.checkpoint.id
  ip_address            = data.google_compute_global_address.checkpoint.address
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
      [for name, instance in module.opsnodes.instances : "serviceAccount:${instance.service_account}"]
    ]),
    flatten([
      for private_api in module.private_apis : [
        for name, instance in private_api.instances : "serviceAccount:${instance.service_account}"
      ]
    ])
  )
}

################################################################################
# OPSNODE SNAPSHOTS SCHEDULE
################################################################################

resource "google_compute_resource_policy" "opsnode_snapshots_schedule" {
  name        = "${var.chain_name}-opsnode-snapshots-schedule"
  region      = var.region
  description = "${var.chain_name} - Opsnode snapshots schedule"

  snapshot_schedule_policy {
    schedule {
      hourly_schedule {
        hours_in_cycle = 1
        start_time     = "03:00"
      }
    }

    retention_policy {
      max_retention_days    = 7
      on_source_disk_delete = "APPLY_RETENTION_POLICY"
    }

    snapshot_properties {
      guest_flush       = true
      storage_locations = [var.region]
      chain_name        = var.chain_name
      labels            = local.labels
    }
  }
}
