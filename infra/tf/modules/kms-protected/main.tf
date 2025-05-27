################################################################################
# KMS KEYRING
################################################################################

locals {
  kms_project_id = substr(var.project_id, 0, 5) == "prj-p" ? var.gcp_p_kms_project_id : var.gcp_d_kms_project_id
}

resource "google_kms_key_ring" "keyring" {
  project  = local.kms_project_id
  name     = "kms-${var.chain_name}"
  location = "global"

  lifecycle {
    prevent_destroy = true
  }
}

################################################################################
# KMS PRIVATE KEYS
################################################################################

resource "google_kms_crypto_key" "node" {
  for_each = var.instances_map

  name     = each.value.name
  key_ring = google_kms_key_ring.keyring.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "node_key_encrypter_decrypter" {
  for_each = var.instances_map

  crypto_key_id = google_kms_crypto_key.node[each.value.name].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${each.value.service_account}"
}

resource "google_kms_crypto_key_iam_member" "node_key_encrypter_decrypter_group_access" {
  for_each = {
    for pair in flatten([
      for key_name, instance in var.instances_map : [
        for member in var.kms_keys_group_access : {
          key_id = google_kms_crypto_key.node[instance.name].id
          member = member
        }
      ]
    ]) : "${pair.key_id}-${pair.member}" => pair
  }

  crypto_key_id = each.value.key_id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "group:${each.value.member}"
}

################################################################################
# KMS STATS DASHBOARD KEY
################################################################################

resource "google_kms_crypto_key" "stats_dashboard" {
  name     = "${var.chain_name}-stats-dashboard"
  key_ring = google_kms_key_ring.keyring.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "stats_dashboard_key_encrypter_decrypter" {
  for_each = merge(var.instances_map, var.instances_apps)

  crypto_key_id = google_kms_crypto_key.stats_dashboard.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${each.value.service_account}"
}

resource "google_kms_crypto_key_iam_member" "stats_dashboard_key_encrypter_decrypter_group_access" {
  for_each = toset(var.kms_keys_group_access)

  crypto_key_id = google_kms_crypto_key.stats_dashboard.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "group:${each.value}"
}

################################################################################
# KMS GENESIS KEY
################################################################################

resource "google_kms_crypto_key" "genesis" {
  name     = "${var.chain_name}-genesis"
  key_ring = google_kms_key_ring.keyring.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "genesis_key_encrypter_decrypter" {
  for_each = var.instances_apps

  crypto_key_id = google_kms_crypto_key.genesis.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${each.value.service_account}"
}

resource "google_kms_crypto_key_iam_member" "genesis_key_encrypter_decrypter_group_access" {
  for_each = toset(var.kms_keys_group_access)

  crypto_key_id = google_kms_crypto_key.genesis.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "group:${each.value}"
}