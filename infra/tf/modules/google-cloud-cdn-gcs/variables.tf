variable "name" {
  description = "The name of the CDN"
  type        = string
}

variable "project_id" {
  description = "The Project ID hosting the CDN related resources"
  type        = string
}

variable "dns_zone_project_id" {
  description = "The Project ID of the project hosting the DNS zone"
  type        = string
  default     = null
}

variable "gcs_bucket_name" {
  description = "The bucket name used as CDN backend"
  type        = string
}

variable "dns_name" {
  description = "The DNS name to be assigned to the CDN external IP."
  type        = string
}

variable "managed_zone" {
  description = "The DNS managed zone name used to host the resource record for the cloud CDN DNS name."
  type        = string
}