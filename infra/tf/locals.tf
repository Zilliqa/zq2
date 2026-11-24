################################################################################
# ZQ2 GCP Terraform locals variables
################################################################################

locals {
  labels       = merge(var.labels, { "zq2-network" = var.chain_name })
  network_name = element(split("/", data.google_compute_subnetwork.default.network), length(split("/", data.google_compute_subnetwork.default.network)) - 1)

  google_load_balancer_ip_ranges = [
    "130.211.0.0/22",
    "35.191.0.0/16",
  ]

  iap_ip_range = "35.235.240.0/20"
  # Egress of the Prometheus exporters (probes on 4202/8080): the prod-apps Cloud NAT, since the exporters moved to
  # gke-p-prod-apps-02-ase1 (devops Phase B, 2026-11-24). 34.87.144.189 (devops-services NAT) is released.
  monitoring_ip_range = "35.247.163.197/32"

  default_service_account_iam = [
    "roles/monitoring.metricWriter=>${var.project_id}",
    "roles/logging.logWriter=>${var.project_id}",
    "roles/cloudtrace.agent=>${var.project_id}",
    "roles/artifactregistry.reader=>${var.gcp_docker_registry_project_id}",
  ]
}
