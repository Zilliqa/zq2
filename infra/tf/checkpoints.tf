################################################################################
# ZQ2 GCP Terraform main resources
################################################################################

resource "google_compute_firewall" "allow_apps_ingress_from_iap" {
  name    = "${var.network_name}-allow-checkpoint-ingress-from-iap"
  network = local.network_name

  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_service_account" "checkpoint" {
  account_id = "${var.network_name}-checkpoint"
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

resource "google_project_iam_member" "checkpoint_bucket_owner" {
  project = var.gcp_docker_registry_project_id
  role    = "roles/storage.legacyBucketOwner"
  member  = "serviceAccount:${google_service_account.checkpoint.email}"
}

module "checkpoint_bucket" {
  source = "./modules/google-cloud-storage"

  names      = ["${var.network_name}-checkpoint-${count.index}"]
  project_id = var.project_id
  location   = "asia-southeast1"
  custom_placement_config = {
    data_locations = ["ASIA-SOUTHEAST1"]
  }

  set_admin_roles  = true
  admins           = ["serviceAccount:${google_service_account.checkpoint.email}"]
  set_viewer_roles = true
  viewers          = ["allUsers"]

  versioning = {
    enabled = true
  }
}

module "checkpoints" {
  source = "./modules/node"
  count  = 1

  name                  = "${var.network_name}-checkpoint-${count.index}"
  service_account_email = google_service_account.checkpoint.email
  network_name          = local.network_name
  node_zone             = data.google_compute_zones.zones.names[0]
  subnetwork_name       = data.google_compute_subnetwork.default.name
  docker_image          = var.docker_image
  persistence_url       = var.persistence_url
  secret_key            = var.checkpoint_secret_keys[count.index]
  role                  = "checkpoint"
  zq_network_name       = var.network_name
}

module "cdn_mainnet_persistence" {
  source = "./modules/google-cloud-cdn-gcs"

  project_id          = var.project_id
  dns_zone_project_id = "prj-p-devops-services-tvwmrf63"
  gcs_bucket_name     = module.checkpoint_bucket.name
  name                = "cdn-${var.network_name}"
  dns_name            = "checkpoints.${var.subdomain}"
  managed_zone        = var.subdomain
}
