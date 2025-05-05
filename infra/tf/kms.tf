locals {
  kms_project_id = substr(var.project_id, 0, 5) == "prj-p" ? var.gcp_p_kms_project_id : var.gcp_d_kms_project_id

  instances_map = merge(
    module.bootstraps.instances,
    module.validators.instances,
    module.apis.instances,
    module.checkpoints.instances,
    module.persistences.instances,
    { for k, v in module.private_apis : k => v.instances }
  )
}

resource "google_kms_key_ring" "keyring" {
  project  = local.kms_project_id
  name     = "kms-${var.chain_name}"
  location = "global"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key" "node" {
  for_each = local.instances_map

  name     = each.value.name
  key_ring = google_kms_key_ring.keyring.id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "key_encrypter_decrypter" {
  for_each = local.instances_map

  crypto_key_id = google_kms_crypto_key.node[each.value.name].id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${each.value.service_account}"
}