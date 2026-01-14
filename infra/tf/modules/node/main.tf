resource "google_service_account" "this" {
  for_each = local.instances_map

  account_id   = "sa-${substr(md5(each.value.resource_name), 0, 27)}"
  display_name = each.value.resource_name
  description  = format("Service account for the node %s", each.value.resource_name)
}

resource "google_project_iam_member" "this" {
  for_each = {
    for pair in flatten([
      for sa_key, sa in google_service_account.this : [
        for iam in var.service_account_iam : {
          sa_key = sa_key
          iam    = iam
        }
      ]
    ]) : "${pair.sa_key}-${pair.iam}" => pair
  }

  project = split("=>", each.value.iam)[1]
  role    = split("=>", each.value.iam)[0]
  member  = "serviceAccount:${google_service_account.this[each.value.sa_key].email}"
}

resource "google_compute_address" "external_regional" {
  for_each = var.config.generate_external_ip ? local.instances_map : {}

  project = data.google_project.current.project_id

  name         = each.value.resource_name
  region       = each.value.region
  network_tier = "PREMIUM"

  labels = merge(local.labels, { "node-name" = each.value.resource_name })
}

resource "google_compute_disk" "data" {
  for_each = {
    for k, v in local.instances_map : k => v
    if v.data_disk_size > 0
  }

  name = "${each.value.resource_name}-data"
  type = "pd-ssd"
  zone = each.value.zone
  size = each.value.data_disk_size

  labels = merge(local.labels, { "node-name" = each.value.resource_name })
 
  lifecycle {
    ignore_changes = [
      snapshot, 
      terraform_labels
    ]
  }
}

resource "google_compute_instance" "this" {
  for_each = local.instances_map

  name                      = each.value.resource_name
  machine_type              = each.value.instance_type
  allow_stopping_for_update = true
  zone                      = each.value.zone

  scheduling {
    provisioning_model = var.config.provisioning_model
    preemptible        = var.config.provisioning_model == "SPOT"
    automatic_restart  = var.config.provisioning_model != "SPOT"

    instance_termination_action = var.config.provisioning_model == "SPOT" ? "STOP" : null
  }

  labels = merge(local.labels, { "node-name" = each.value.resource_name })

  service_account {
    email = google_service_account.this[each.value.resource_id].email
    scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write",
      "https://www.googleapis.com/auth/compute", # REMOVE
    ]
  }

  boot_disk {
    initialize_params {
      size  = each.value.boot_disk_size
      image = each.value.image
      type  = "pd-ssd"
    }
  }

  dynamic "attached_disk" {
    for_each = each.value.data_disk_size > 0 ? [1] : []
    content {
      source      = google_compute_disk.data[each.key].id
      device_name = "data"
      mode        = "READ_WRITE"
    }
  }

  network_interface {
    network    = data.google_compute_subnetworks.default[each.value.region].subnetworks[0].network_self_link
    subnetwork = data.google_compute_subnetworks.default[each.value.region].subnetworks[0].name

    dynamic "access_config" {
      for_each = [var.role == "validator" ? 1 : 0] # Always create the access_config block for validators
      content {
        nat_ip = var.config.generate_external_ip ? google_compute_address.external_regional[each.value.resource_id].address : null
      }
    }
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  tags = local.network_tags

  metadata = merge(
    {
      "enable-guest-attributes" = "TRUE"
      "enable-osconfig"         = "TRUE"
    },
    var.metadata,
  )

  lifecycle {
    ignore_changes = [
      labels["peer-id"]
    ]
  }
}
