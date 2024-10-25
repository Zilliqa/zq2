################################################################################
# ZQ2 GCP Terraform checkpoint resources
################################################################################

module "checkpoints" {
  source = "./modules/node"

  config     = var.checkpoint
  chain_name = var.chain_name

  role                   = "checkpoint"
  labels                 = {}
  network_tags           = []
  generate_node_key      = true
  generate_reward_wallet = false

  metadata = {
    persistence_url = base64encode(var.persistence_url)
    subdomain       = base64encode("")
    genesis_key     = base64encode("")
  }

  node_dns_subdomain       = var.node_dns_subdomain
  node_dns_zone_project_id = var.node_dns_zone_project_id

  service_account_iam = local.default_service_account_iam
}

resource "google_compute_instance_group" "checkpoint" {
  for_each = toset(module.checkpoints.zones)

  name      = "${var.chain_name}-checkpoint-${each.key}"
  zone      = each.key
  instances = [for instance in module.checkpoints.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_storage_bucket" "checkpoint" {
  name     = join("-", compact([var.chain_name, "checkpoint"]))
  project  = var.project_id
  location = var.region
  labels   = local.labels

  force_destroy               = var.checkpoint.bucket_force_destroy
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"

  versioning {
    enabled = true
  }
}

resource "google_storage_bucket_iam_binding" "checkpoint_bucket_admins" {
  bucket  = google_storage_bucket.checkpoint.name
  role    = "roles/storage.objectAdmin"
  members = ["serviceAccount:${module.checkpoints.service_account.email}"]
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

resource "google_compute_url_map" "checkpoint" {
  name            = format("%s-checkpoint-cdn", var.chain_name)
  default_service = google_compute_backend_bucket.checkpoint.id
}

resource "google_compute_managed_ssl_certificate" "checkpoint" {
  name = format("%s-checkpoint-cdn", var.chain_name)

  managed {
    domains = [format("checkpoints.%s", var.subdomain)]
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
  url_map = google_compute_url_map.checkpoint.id
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
