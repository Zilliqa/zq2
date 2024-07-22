<!-- BEGIN_TF_DOCS -->
## Providers

| Name | Version |
|------|---------|
| <a name="provider_google"></a> [google](#provider\_google) | >= 4.50, < 5.0 |
| <a name="provider_google-beta"></a> [google-beta](#provider\_google-beta) | >= 4.50, < 5.0 |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_dns_name"></a> [dns\_name](#input\_dns\_name) | The DNS name to be assigned to the CDN external IP. | `string` | n/a | yes |
| <a name="input_dns_zone_project_id"></a> [dns\_zone\_project\_id](#input\_dns\_zone\_project\_id) | The Project ID of the project hosting the DNS zone | `string` | `null` | no |
| <a name="input_gcs_bucket_name"></a> [gcs\_bucket\_name](#input\_gcs\_bucket\_name) | The bucket name used as CDN backend | `string` | n/a | yes |
| <a name="input_managed_zone"></a> [managed\_zone](#input\_managed\_zone) | The DNS managed zone name used to host the resource record for the cloud CDN DNS name. | `string` | n/a | yes |
| <a name="input_name"></a> [name](#input\_name) | The name of the CDN | `string` | n/a | yes |
| <a name="input_project_id"></a> [project\_id](#input\_project\_id) | The Project ID hosting the CDN related resources | `string` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_cdn_external_ip"></a> [cdn\_external\_ip](#output\_cdn\_external\_ip) | ################### Outputs ################### |
| <a name="output_cdn_name"></a> [cdn\_name](#output\_cdn\_name) | n/a |
<!-- END_TF_DOCS -->