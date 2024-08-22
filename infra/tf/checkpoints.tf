################################################################################
# ZQ2 GCP Terraform checkpoint resources
################################################################################

resource "google_compute_firewall" "allow_checkpoint_ingress_from_iap" {
  name    = "${var.network_name}-allow-checkpoint-ingress-from-iap"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "allow_checkpoint_p2p" {
  name    = "${var.network_name}-allow-checkpoint-p2p"
  network = local.network_name


  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["3333"]
  }
}

resource "google_compute_firewall" "allow_checkpoint_external_jsonrpc" {
  name    = "${var.network_name}-allow-checkpoint-external-jsonrpc"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["4201"]
  }
}

resource "google_service_account" "checkpoint" {
  account_id = substr("${var.network_name}-checkpoint", 0, 28)
}

data "google_project" "checkpoint" {}

resource "google_project_iam_member" "checkpoint_metric_writer" {
  project = data.google_project.checkpoint.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.checkpoint.email}"
}

resource "google_project_iam_member" "checkpoint_log_writer" {
  project = data.google_project.checkpoint.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.checkpoint.email}"
}

resource "google_project_iam_member" "checkpoint_artifact_registry_reader" {
  project = var.gcp_docker_registry_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.checkpoint.email}"
}

resource "google_project_iam_member" "checkpoint_secret_manager_accessor" {
  project = data.google_project.checkpoint.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.checkpoint.email}"
}

resource "google_project_iam_member" "checkpoint_bucket_owner" {
  project = data.google_project.checkpoint.project_id
  role    = "roles/storage.objectAdmin"
  member  = "serviceAccount:${google_service_account.checkpoint.email}"
}

module "checkpoints" {
  source = "./modules/node"
  vm_num = 1

  name                  = "${var.network_name}-node-checkpoint"
  service_account_email = google_service_account.checkpoint.email
  dns_zone_project_id   = var.dns_zone_project_id
  nodes_dns_zone_name   = var.nodes_dns_zone_name
  network_name          = local.network_name
  node_zones            = local.default_zones
  subnetwork_name       = data.google_compute_subnetwork.default.name
  persistence_url       = var.persistence_url
  role                  = "checkpoint"
  zq_network_name       = var.network_name
}

resource "google_compute_instance_group" "checkpoint" {
  for_each = toset(local.default_zones)

  name      = "${var.network_name}-checkpoint-${each.key}"
  zone      = each.key
  instances = [for instance in module.checkpoints.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}

resource "google_storage_bucket" "checkpoint" {
  name     = join("-", compact([var.network_name, "checkpoint"]))
  project  = var.project_id
  location = var.region
  labels   = local.labels

  force_destroy               = false
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"

  versioning {
    enabled = true
  }
}

resource "google_storage_bucket_iam_binding" "checkpoint_bucket_admins" {
  bucket  = google_storage_bucket.checkpoint.name
  role    = "roles/storage.objectAdmin"
  members = ["serviceAccount:${google_service_account.checkpoint.email}"]
}

resource "google_storage_bucket_iam_binding" "checkpoint_bucket_viewers" {
  bucket  = google_storage_bucket.checkpoint.name
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}

# backend bucket with CDN policy with default ttl settings
resource "google_compute_backend_bucket" "checkpoint" {
  name        = format("cdn-%s-backend", var.network_name)
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
  name            = format("%s-checkpoint-cdn", var.network_name)
  default_service = google_compute_backend_bucket.checkpoint.id
}

resource "google_compute_managed_ssl_certificate" "checkpoint" {
  name = format("%s-checkpoint-cdn", var.network_name)

  managed {
    domains = [format("checkpoints.%s", var.subdomain)]
  }
}

resource "google_compute_ssl_policy" "tls12_modern" {
  project         = var.project_id
  name            = format("%s-checkpoint-cdn", var.network_name)
  profile         = "COMPATIBLE"
  min_tls_version = "TLS_1_2"
}

resource "google_compute_target_http_proxy" "checkpoint" {
  name    = format("%s-checkpoint-cdn", var.network_name)
  url_map = google_compute_url_map.checkpoint.id
}

resource "google_compute_target_https_proxy" "checkpoint" {
  name             = format("%s-checkpoint-cdn", var.network_name)
  url_map          = google_compute_url_map.checkpoint.id
  ssl_certificates = [google_compute_managed_ssl_certificate.checkpoint.id]
  ssl_policy       = google_compute_ssl_policy.tls12_modern.id
}

data "google_compute_global_address" "checkpoint" {
  name = "checkpoints-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_global_forwarding_rule" "checkpoint_http" {
  name                  = "${var.network_name}-checkpoint-forwarding-rule-http"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "80"
  target                = google_compute_target_http_proxy.checkpoint.id
  ip_address            = data.google_compute_global_address.checkpoint.address
}

resource "google_compute_global_forwarding_rule" "checkpoint_https" {
  name                  = "${var.network_name}-checkpoint-forwarding-rule-https"
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = "443"
  target                = google_compute_target_https_proxy.checkpoint.id
  ip_address            = data.google_compute_global_address.checkpoint.address
}
