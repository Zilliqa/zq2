################################################################################
# ZQ2 GCP Terraform input variables
################################################################################


variable "project_id" {
  description = "Project ID used to dpeloy the ZQ2 network"
  type        = string
  nullable    = false
}

variable "region" {
  description = "The region ID to host the network in"
  type        = string
  default     = "europe-west2"
}

variable "node_zone" {
  type     = string
  default  = "europe-west2-a"
  nullable = false
}

variable "eth_chain_id" {
  description = "ZQ2 EVM Chain ID"
  type        = number
  nullable    = false
}

variable "subdomain" {
  type     = string
  nullable = false
}

variable "network_name" {
  description = "(Optional) ZQ2 network name"
  type        = string
  nullable    = false
  default     = "zq2-devnet"
}

variable "labels" {
  type        = map(string)
  description = "A single-level map/object with key value pairs of metadata labels to apply to the GCP resources. All keys should use underscores and values should use hyphens. All values must be wrapped in quotes."
  nullable    = true
  default     = {}
}

variable "vpc_main_subnet_name" {
  description = "(Optional) ZQ2 VPC subnet name"
  type        = string
  nullable    = false
}


variable "genesis_key" {
  description = "(Optional) Genesis private key"
  type        = string
  nullable    = false
}

variable "bootstrap_key" {
  description = "(Optional) Boostrap node private key"
  type        = string
  nullable    = false
}

variable "node_count" {
  description = "(Optional) ZQ2 Node count"
  type        = number
  nullable    = false
  default     = 3
}

variable "secret_keys" {
  description = "(Optional) ZQ2 Nodes secret keys"
  type        = list(string)
  nullable    = false
}


variable "persistence_url" {
  description = "(Optional) ZQ2 Recovery persistence URL"
  type        = string
  nullable    = true
  default     = ""
}