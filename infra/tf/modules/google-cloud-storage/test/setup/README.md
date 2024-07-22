# Integration Testing

Use this directory to create resources reflecting the same resource fixtures
created for use by the CI environment CI integration test pipelines.  The intent
of these resources is to run the integration tests locally as closely as
possible to how they will run in the CI system.

Once created, store the service account key content into the
`SERVICE_ACCOUNT_JSON` environment variable. This reflects the same behavior
as used in CI.

For example:

```bash
terraform init
terraform apply
mkdir -p ~/.credentials
terraform output sa_key | base64 --decode > ~/.credentials/cloud-storage-sa.json
```

Then, configure the environment (suggest using direnv) like so:

```bash
export SERVICE_ACCOUNT_JSON=$(cat ${HOME}/.credentials/cloud-storage-sa.json)
export PROJECT_ID="cloud-storage-module"
```

With these variables set, change to the root of the module and execute the
`make test_integration` task. This make target is the same that is executed
by this module's CI pipeline during integration testing, and will run the
integration tests from your machine.

Alternatively, to run the integration tests directly from the Docker
container used by the module's CI pipeline, perform the above steps and then
run the `make test_integration_docker` target

<!-- BEGIN_TF_DOCS -->
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.13 |
| <a name="requirement_google"></a> [google](#requirement\_google) | >= 3.53.0, < 5.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_google"></a> [google](#provider\_google) | >= 3.53.0, < 5.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_project"></a> [project](#module\_project) | terraform-google-modules/project-factory/google | ~> 14.0 |

## Resources

| Name | Type |
|------|------|
| [google_project_iam_member.int_test](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/project_iam_member) | resource |
| [google_service_account.int_test](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/service_account) | resource |
| [google_service_account_key.int_test](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/service_account_key) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_billing_account"></a> [billing\_account](#input\_billing\_account) | The billing account id associated with the project, e.g. XXXXXX-YYYYYY-ZZZZZZ | `any` | n/a | yes |
| <a name="input_folder_id"></a> [folder\_id](#input\_folder\_id) | The folder to deploy in | `any` | n/a | yes |
| <a name="input_org_id"></a> [org\_id](#input\_org\_id) | The numeric organization id | `any` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_project_id"></a> [project\_id](#output\_project\_id) | n/a |
| <a name="output_sa_key"></a> [sa\_key](#output\_sa\_key) | n/a |
<!-- END_TF_DOCS -->