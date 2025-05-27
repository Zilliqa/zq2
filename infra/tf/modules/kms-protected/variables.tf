variable "project_id" {
  description = "Project ID used to dpeloy the ZQ2 network"
  type        = string
  nullable    = false
}

variable "chain_name" {
  description = "(Optional) ZQ2 blockchain name"
  type        = string
  nullable    = false
  default     = "zq2-devnet"
}

variable "instances_map" {
  description = "Merged map of all instances from bootstraps, validators, apis, checkpoints, persistences, and private_apis modules"
  type = map(object({
    name            = string
    external_ip     = string
    zone            = string
    self_link       = string
    service_account = string
  }))
  default = {}
}

variable "instances_apps" {
  description = "Map of app instances from the apps module"
  type = map(object({
    name            = string
    external_ip     = string
    zone            = string
    self_link       = string
    service_account = string
  }))
  default = {}
}

variable "gcp_d_kms_project_id" {
  description = "(Optional) Non production KMS project id"
  type        = string
  default     = "prj-d-kms-tw1xyxbh"
}

variable "gcp_p_kms_project_id" {
  description = "(Optional) KMS production project id"
  type        = string
  default     = "prj-p-kms-2vduab0g"
}

variable "kms_keys_group_access" {
  description = "(Optional) List of groups to grant access to the KMS keys"
  type        = list(string)
  default     = []
}