################################################################################
# ZQ2 GCP Terraform outputs
################################################################################

output "api_external_ip" {
  description = "The provisioned bootstrap external IPs"
  value       = module.apis.external_ip
}

output "bootstrap_external_ip" {
  description = "The provisioned bootstrap external IPs"
  value       = module.bootstraps.external_ip
}

output "bootstrap_dns_names" {
  description = "The provisioned bootstrap DNS names"
  value = length(module.bootstraps.external_ip) > 0 ? merge(
    { "bootstrap.${var.chain_name}" = module.bootstraps.external_ip[keys(module.bootstraps.external_ip)[0]] },
    { for idx, key in keys(module.bootstraps.external_ip) : "bootstrap-${idx}.${var.chain_name}" => module.bootstraps.external_ip[key] }
  ) : {}
}

output "validator_external_ip" {
  description = "The provisioned bootstrap external IPs"
  value       = module.validators.external_ip
}

output "opsnode_external_ip" {
  description = "The provisioned opsnode external IPs"
  value       = module.opsnodes.external_ip
}

output "private_api_external_ip" {
  description = "The provisioned private APIs external IPs"
  value = merge(flatten([
    for private_api in module.private_apis : private_api.external_ip
  ])...)
}

output "instances_map" {
  description = "Merged map of all instances from bootstraps, validators, apis, opsnodes, and private_apis modules"
  value = merge(
    module.bootstraps.instances,
    module.validators.instances,
    module.apis.instances,
    module.opsnodes.instances,
    merge([for private_api in module.private_apis : private_api.instances]...)
  )
}

output "instances_apps" {
  description = "Map of app instances from the apps module"
  value       = module.apps.instances
}