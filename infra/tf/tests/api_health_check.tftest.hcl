# ABOUTME: Plan-only tests for the load balancer health check that decides which API nodes get traffic.
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

run "a_busy_node_stays_in_the_pool" {
  command = plan

  # Under load the JSON-RPC runtime freezes for up to 6 s (2026-11-24). /health waits up to 7 s for port 4201
  # (healthcheck.py.j2), so the probe needs more time than that, or a busy node is taken out and its traffic
  # lands on the other node, which then freezes in turn.
  assert {
    condition     = google_compute_health_check.api.timeout_sec == 10
    error_message = "The probe waits longer than the node's own 7 s JSON-RPC check"
  }

  assert {
    condition     = google_compute_health_check.api.check_interval_sec == 10
    error_message = "The probe interval is at least its timeout"
  }

  assert {
    condition     = google_compute_health_check.api.unhealthy_threshold == 3
    error_message = "A node is taken out after 3 failed probes (30 s)"
  }
}
