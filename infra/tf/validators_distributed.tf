################################################################################
# ZQ2 GCP Terraform multi-region / zones validators
################################################################################

resource "google_service_account" "validators" {
  count      = length(var.distributed_validators) >= 1 ? 1 : 0
  account_id = substr("${var.network_name}-validators", 0, 28)
}

resource "google_project_iam_member" "validators_metric_writer" {
  count   = length(var.distributed_validators) >= 1 ? 1 : 0
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.validators[0].email}"
}

resource "google_project_iam_member" "validators_log_writer" {
  count   = length(var.distributed_validators) >= 1 ? 1 : 0
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.validators[0].email}"
}

resource "google_project_iam_member" "validators_artifact_registry_reader" {
  count   = length(var.distributed_validators) >= 1 ? 1 : 0
  project = var.gcp_docker_registry_project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.validators[0].email}"
}

resource "google_project_iam_member" "validators_secret_manager_accessor" {
  count   = length(var.distributed_validators) >= 1 ? 1 : 0
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.validators[0].email}"
}

data "google_compute_zones" "validators_zones" {
  for_each = { for idx, val in var.distributed_validators : idx => val }
  project  = var.project_id
  region   = each.value.region
}

module "distributed_validators" {
  for_each = { for idx, val in var.distributed_validators : idx => val }
  source   = "./modules/node"

  vm_num = each.value.vm_num

  name                   = "${var.network_name}-node-validator-${each.value.region}"
  service_account_email  = google_service_account.validators[0].email
  dns_zone_project_id    = var.dns_zone_project_id
  nodes_dns_zone_name    = var.nodes_dns_zone_name
  network_name           = local.network_name
  node_zones             = each.value.vm_zone != null ? [each.value.vm_zone] : data.google_compute_zones.validators_zones[each.key].names
  subnetwork_name        = each.value.vpc_subnet_name
  persistence_url        = var.persistence_url
  role                   = "validator"
  zq_network_name        = var.network_name
  generate_reward_wallet = true
  provisioning_model     = var.provisioning_model
  node_type              = var.node_type
}
