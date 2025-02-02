################################################################################
# PERFORMANCE TESTS BUCKET
################################################################################

resource "google_storage_bucket" "performance_tests" {
  name     = join("-", compact([var.chain_name, "performance-tests"]))
  project  = var.project_id
  location = var.region
  labels   = local.labels

  force_destroy               = var.persistence_bucket_force_destroy
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"

  versioning {
    enabled = false
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
    condition {
      age = 7
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
    condition {
      age = 37 # 7 days in Standard + 30 days in Nearline
    }
  }

  lifecycle_rule {
    action {
      type          = "SetStorageClass"
      storage_class = "ARCHIVE"
    }
    condition {
      age = 127 # 37 days + 90 days in Coldline
    }
  }
}

resource "google_storage_bucket_iam_binding" "performance_tests_bucket_admins" {
  bucket  = google_storage_bucket.performance_tests.name
  role    = "roles/storage.objectAdmin"
  members = ["serviceAccount:${var.testing_service_account}"]
}