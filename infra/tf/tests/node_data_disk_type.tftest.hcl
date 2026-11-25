# ABOUTME: Plan-only tests for the data disk type of the zq2 node module (pd-ssd unless a role asks for another type).
# ABOUTME: Uses a mocked google provider, so it needs no GCP credentials: run `terraform init && terraform test` in infra/tf.

mock_provider "google" {
  mock_data "google_compute_zones" {
    defaults = {
      names = ["asia-southeast1-a", "asia-southeast1-b"]
    }
  }
  mock_data "google_compute_subnetworks" {
    defaults = {
      subnetworks = [{
        name              = "sb-test"
        network_self_link = "projects/prj-test/global/networks/test-network"
      }]
    }
  }
}

variables {
  chain_name = "zq2-test"
  role       = "bootstrap"
}

run "data_disks_stay_ssd_by_default" {
  command = plan

  module {
    source = "./modules/node"
  }

  variables {
    config = {
      data_disk_size = 1800
      nodes          = [{ count = 1, region = "asia-southeast1" }]
    }
  }

  assert {
    condition     = alltrue([for disk in google_compute_disk.data : disk.type == "pd-ssd"])
    error_message = "A node keeps its pd-ssd data disk unless its role asks for another type: changing the type replaces the disk"
  }
}

run "a_role_can_ask_for_balanced_data_disks" {
  command = plan

  module {
    source = "./modules/node"
  }

  variables {
    config = {
      data_disk_size = 1800
      data_disk_type = "pd-balanced"
      nodes          = [{ count = 1, region = "asia-southeast1" }]
    }
  }

  assert {
    condition     = length(google_compute_disk.data) == 1 && alltrue([for disk in google_compute_disk.data : disk.type == "pd-balanced"])
    error_message = "The data disk takes the type the role configures"
  }
}

run "an_unknown_disk_type_is_refused" {
  command = plan

  module {
    source = "./modules/node"
  }

  variables {
    config = {
      data_disk_size = 1800
      data_disk_type = "pd-standard-typo"
      nodes          = [{ count = 1, region = "asia-southeast1" }]
    }
  }

  expect_failures = [var.config]
}
