################################################################################
# ZQ2 GCP Terraform validator resources
################################################################################

resource "google_service_account" "validator" {
  account_id = substr("${var.network_name}-validator", 0, 28)
}

resource "google_project_iam_member" "validator_metric_writer" {
  project = data.google_project.this.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.validator.email}"
}

resource "google_project_iam_member" "validator_log_writer" {
  project = data.google_project.this.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.validator.email}"
}

resource "google_project_iam_member" "validator_artifact_registry_reader" {
  project = var.gcp_docker_registry_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.validator.email}"
}

resource "google_project_iam_member" "validator_secret_manager_accessor" {
  project = data.google_project.this.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.validator.email}"
}

module "validators" {
  source = "./modules/node"
  vm_num = var.validator_node_count

  name                   = "${var.network_name}-node-validator"
  service_account_email  = google_service_account.validator.email
  dns_zone_project_id    = var.dns_zone_project_id
  nodes_dns_zone_name    = var.nodes_dns_zone_name
  network_name           = local.network_name
  node_zones             = local.default_zones
  subnetwork_name        = data.google_compute_subnetwork.default.name
  persistence_url        = var.persistence_url
  role                   = "validator"
  zq_network_name        = var.network_name
  generate_reward_wallet = true
  provisioning_model     = var.provisioning_model
  node_type              = var.node_type
}

resource "google_compute_instance_group" "validator" {
  for_each = toset(local.default_zones)

  name      = "${var.network_name}-validator-${each.key}"
  zone      = each.key
  instances = [for instance in module.validators.instances : instance.self_link if instance.zone == each.key]

  named_port {
    name = "jsonrpc"
    port = "4201"
  }
}
