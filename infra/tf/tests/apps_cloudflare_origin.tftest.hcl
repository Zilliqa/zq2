# ABOUTME: Plan-only tests for apps.cloudflare_origin: Cloudflare-only firewall and optional apps load balancer removal.
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

run "load_balancer_only_by_default" {
  command = plan

  assert {
    condition     = length(google_compute_firewall.allow_apps_cloudflare) == 0
    error_message = "No Cloudflare firewall rule unless cloudflare_origin.enabled is set"
  }

  assert {
    condition     = length(google_compute_global_forwarding_rule.otterscan_https) == 1 && length(google_compute_global_forwarding_rule.stats_https) == 1
    error_message = "The apps load balancer must exist by default"
  }

  assert {
    condition     = length(google_compute_firewall.allow_apps_external_http) == 1
    error_message = "The load balancer firewall rule must exist by default"
  }
}

run "cloudflare_origin_next_to_load_balancer" {
  command = plan

  variables {
    apps = {
      enable_faucet = false
      cloudflare_origin = {
        enabled     = true
        ipv4_ranges = ["173.245.48.0/20", "103.21.244.0/22"]
      }
    }
  }

  assert {
    condition     = google_compute_firewall.allow_apps_cloudflare[0].source_ranges == toset(["173.245.48.0/20", "103.21.244.0/22"])
    error_message = "The Cloudflare firewall rule must allow exactly the given ranges"
  }

  assert {
    condition     = one(google_compute_firewall.allow_apps_cloudflare[0].allow).ports == tolist(["443"])
    error_message = "The Cloudflare firewall rule must only open port 443"
  }

  assert {
    condition     = google_compute_firewall.allow_apps_cloudflare[0].target_tags == toset(["zq2-test-apps"])
    error_message = "The Cloudflare firewall rule must target the apps nodes only"
  }

  assert {
    condition     = length(google_compute_global_forwarding_rule.otterscan_https) == 1
    error_message = "The load balancer stays until remove_load_balancer is set"
  }
}

run "cloudflare_origin_without_load_balancer" {
  command = plan

  variables {
    apps = {
      enable_faucet = false
      cloudflare_origin = {
        enabled              = true
        ipv4_ranges          = ["173.245.48.0/20"]
        remove_load_balancer = true
      }
    }
  }

  assert {
    condition     = length(google_compute_firewall.allow_apps_cloudflare) == 1
    error_message = "The Cloudflare firewall rule must remain"
  }

  assert {
    condition = alltrue([
      length(google_compute_global_forwarding_rule.otterscan_http) == 0,
      length(google_compute_global_forwarding_rule.otterscan_https) == 0,
      length(google_compute_global_forwarding_rule.stats_http) == 0,
      length(google_compute_global_forwarding_rule.stats_https) == 0,
      length(google_compute_target_http_proxy.apps) == 0,
      length(google_compute_target_https_proxy.apps) == 0,
      length(google_compute_managed_ssl_certificate.apps) == 0,
      length(google_compute_url_map.apps) == 0,
      length(google_compute_url_map.apps_http_redirect) == 0,
      length(google_compute_backend_service.otterscan) == 0,
      length(google_compute_backend_service.stats) == 0,
      length(google_compute_health_check.otterscan) == 0,
      length(google_compute_health_check.stats) == 0,
      length(google_compute_instance_group.apps) == 0,
      length(google_compute_firewall.allow_apps_external_http) == 0,
      length(data.google_compute_global_address.otterscan) == 0,
      length(data.google_compute_global_address.stats) == 0,
    ])
    error_message = "remove_load_balancer must drop every apps load balancer resource"
  }
}

run "remove_load_balancer_requires_cloudflare_origin" {
  command = plan

  variables {
    apps = {
      enable_faucet = false
      cloudflare_origin = {
        remove_load_balancer = true
      }
    }
  }

  expect_failures = [var.apps]
}

run "cloudflare_origin_requires_ranges" {
  command = plan

  variables {
    apps = {
      enable_faucet = false
      cloudflare_origin = {
        enabled = true
      }
    }
  }

  expect_failures = [var.apps]
}

run "remove_load_balancer_rejects_faucet" {
  command = plan

  variables {
    apps = {
      enable_faucet = true
      cloudflare_origin = {
        enabled              = true
        ipv4_ranges          = ["173.245.48.0/20"]
        remove_load_balancer = true
      }
    }
  }

  expect_failures = [var.apps]
}
