# ABOUTME: Plan-only tests for the monitoring probe source allowed on the node health and JSON-RPC ports.
# ABOUTME: Uses a mocked google provider, so it needs no GCP credentials: run `terraform init && terraform test` in infra/tf.

mock_provider "google" {
  mock_data "google_compute_subnetwork" {
    defaults = {
      network = "projects/prj-test/global/networks/test-network"
    }
  }
}

variables {
  project_id           = "prj-test"
  chain_name           = "zq2-test"
  subdomain            = "zq2-test.zilliqa.com"
  vpc_main_subnet_name = "sb-test"
  apps = {
    enable_faucet = false
  }
}

run "probes_come_from_the_prod_apps_cluster" {
  command = plan

  # The Prometheus exporters run on gke-p-prod-apps-02-ase1 and leave through the prod-apps Cloud NAT.
  assert {
    condition     = google_compute_firewall.allow_monitor_healthcheck.source_ranges == toset(["35.247.163.197/32"])
    error_message = "Node health (8080) is open to the prod-apps NAT egress only"
  }

  assert {
    condition     = contains(tolist(google_compute_firewall.allow_jsonrpc_from_iap.source_ranges), "35.247.163.197/32")
    error_message = "Node JSON-RPC (4202) is open to the prod-apps NAT egress"
  }
}

run "released_devops_services_ip_is_gone" {
  command = plan

  # 34.87.144.189 was the devops-services NAT egress; that cluster is retired and the IP released.
  assert {
    condition = alltrue([
      !contains(tolist(google_compute_firewall.allow_monitor_healthcheck.source_ranges), "34.87.144.189/32"),
      !contains(tolist(google_compute_firewall.allow_jsonrpc_from_iap.source_ranges), "34.87.144.189/32"),
      !contains(tolist(google_compute_firewall.allow_api_external_http.source_ranges), "34.87.144.189/32"),
    ])
    error_message = "The released devops-services NAT IP must not be allowed anywhere"
  }
}
