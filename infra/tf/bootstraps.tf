################################################################################
# ZQ2 GCP Terraform bootstraps resources
################################################################################

resource "google_service_account" "bootstrap" {
  account_id = substr("${var.network_name}-bootstrap", 0, 28)
}

resource "google_project_iam_member" "bootstrap_metric_writer" {
  project = data.google_project.this.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.bootstrap.email}"
}

resource "google_project_iam_member" "bootstrap_log_writer" {
  project = data.google_project.this.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.bootstrap.email}"
}

resource "google_project_iam_member" "bootstrap_artifact_registry_reader" {
  project = var.gcp_docker_registry_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.bootstrap.email}"
}

resource "google_project_iam_member" "bootstrap_secret_manager_accessor" {
  project = data.google_project.this.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.bootstrap.email}"
}

module "bootstrap_node" {
  source = "./modules/node"
  vm_num = 1

  name                  = "${var.network_name}-node-bootstrap"
  service_account_email = google_service_account.bootstrap.email
  dns_zone_project_id   = var.dns_zone_project_id
  nodes_dns_zone_name   = var.nodes_dns_zone_name
  node_zones            = local.default_zones
  network_name          = local.network_name
  subnetwork_name       = data.google_compute_subnetwork.default.name
  external_ip           = data.google_compute_address.bootstrap.address
  persistence_url       = var.persistence_url
  zq_network_name       = var.network_name
  role                  = "bootstrap"
  labels                = local.labels
  provisioning_model    = var.provisioning_model
  node_type             = var.node_type
}

data "google_compute_address" "bootstrap" {
  name = "bootstrap-${replace(var.subdomain, ".", "-")}"
}

resource "google_compute_instance_group" "bootstrap" {
  name      = "${var.network_name}-bootstrap"
  zone      = var.node_zone != "" ? var.node_zone : data.google_compute_zones.zones.names[0]
  instances = module.bootstrap_node.self_link

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}
