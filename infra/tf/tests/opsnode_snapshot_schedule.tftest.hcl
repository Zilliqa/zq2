# ABOUTME: Plan-only tests for the opsnode data disk snapshot schedule (hourly unless the network asks for daily) and disk types.
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

run "opsnode_snapshots_are_hourly_by_default" {
  command = plan

  assert {
    condition = (
      length(google_compute_resource_policy.opsnode_snapshots_schedule.snapshot_schedule_policy[0].schedule[0].hourly_schedule) == 1
      && length(google_compute_resource_policy.opsnode_snapshots_schedule.snapshot_schedule_policy[0].schedule[0].daily_schedule) == 0
    )
    error_message = "Networks that do not choose keep an hourly opsnode snapshot"
  }

  assert {
    condition     = google_compute_resource_policy.opsnode_snapshots_schedule.snapshot_schedule_policy[0].retention_policy[0].max_retention_days == 7
    error_message = "Opsnode snapshots are kept 7 days"
  }
}

run "a_network_can_take_daily_opsnode_snapshots" {
  command = plan

  variables {
    opsnode = {
      snapshot_frequency = "daily"
    }
  }

  # 2026-11-25, mainnet: hourly snapshots kept 7 days were 168 snapshots and 3.5 TB (decision log C5: 7 daily).
  assert {
    condition = (
      length(google_compute_resource_policy.opsnode_snapshots_schedule.snapshot_schedule_policy[0].schedule[0].daily_schedule) == 1
      && google_compute_resource_policy.opsnode_snapshots_schedule.snapshot_schedule_policy[0].schedule[0].daily_schedule[0].days_in_cycle == 1
      && length(google_compute_resource_policy.opsnode_snapshots_schedule.snapshot_schedule_policy[0].schedule[0].hourly_schedule) == 0
    )
    error_message = "A daily opsnode snapshot replaces the hourly one"
  }

  assert {
    condition     = google_compute_resource_policy.opsnode_snapshots_schedule.snapshot_schedule_policy[0].retention_policy[0].max_retention_days == 7
    error_message = "Daily snapshots are kept 7 days too"
  }
}

run "an_unknown_snapshot_frequency_is_refused" {
  command = plan

  variables {
    opsnode = {
      snapshot_frequency = "weekly"
    }
  }

  expect_failures = [var.opsnode]
}

run "bootstrap_and_opsnode_pass_their_data_disk_type_to_the_nodes" {
  command = plan

  variables {
    bootstrap = {
      data_disk_size = 1800
      data_disk_type = "pd-balanced"
      nodes          = [{ count = 1, region = "asia-southeast1" }]
    }
    opsnode = {
      data_disk_size = 1800
      data_disk_type = "pd-balanced"
      nodes          = [{ count = 1, region = "asia-southeast1" }]
    }
  }

  assert {
    condition     = var.bootstrap.data_disk_type == "pd-balanced" && var.opsnode.data_disk_type == "pd-balanced"
    error_message = "The bootstrap and opsnode roles accept a data disk type"
  }
}
