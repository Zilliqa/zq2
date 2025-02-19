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

output "checkpoint_external_ip" {
  description = "The provisioned bootstrap external IPs"
  value       = module.checkpoints.external_ip
}

output "persistence_external_ip" {
  description = "The provisioned bootstrap external IPs"
  value       = module.persistences.external_ip
}

output "private_api_dns_names" {
  description = "The provisioned private API DNS names"
  value = merge(flatten([
    for name, private_api in module.private_apis : {
      for idx, key in keys(private_api.external_ip) : format("%s.%s", var.private_api[name].dns_names[idx], var.chain_name) => private_api.external_ip[key]
    }
  ])...)
}
