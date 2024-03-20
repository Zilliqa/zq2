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
  default     = 33469
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

variable "zq2_type" {
  type        = string
  description = "(Optional) ZQ2 deployment type"
  default     = "devnet"
  validation {
    condition     = contains(["devnet", "proto-testnet", "proto-mainnet", "testnet", "mainnet"], var.zq2_type)
    error_message = "Valid values is one of the following: devnet, proto-testnet, proto-mainnent, testnet, mainnet"
  }
  nullable = false
}

variable "vpc_main_subnet_name" {
  description = "(Optional) ZQ2 VPC subnet name"
  type        = string
  nullable    = true
  default     = ""
}
variable "subnet_cidr" {
  description = "(Optional) ZQ2 VPC subnet CIDR"
  type        = string
  default     = "10.2.0.0/20"
}

variable "proxy_subnet_cidr" {
  description = "(Optional) ZQ2 VPC subnet CIDR"
  type        = string
  default     = "10.3.0.0/20"
}

variable "genesis_key" {
  description = "(Optional) Genesis private key"
  type        = string
  nullable    = true
  default     = ""
}

variable "bootstrap_key" {
  description = "(Optional) Boostrap node private key"
  type        = string
  nullable    = true
  default     = ""

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
  nullable    = true
  default     = []
}