# Using Terraform to Create an Environment

## Overview

GitLab Provisioner uses [terraform][tfhome] to create a cluster of virtual
machines on [Google Cloud][tfgoogle]. The [terraform][tfhome] job expects
variables set as environment variables or in a `terraform.tfvars` file.

**NOTE**: [Terraform][tfhome] must be version 0.12 or greater.

## Getting Started

### How Terraform Stores Current State

[Terraform][tfhome] stores cluster state data in
`.terraform/terraform.tfstate` by default. Configuring the `prefix` and
`bucket` variables will enable storage in a remote bucket instead and is
useful for sharing state among multiple administrators. The following
resources provide some useful background information.

- [Learn to create buckets in Google Cloud](https://cloud.google.com/storage/docs/creating-buckets)
- [Learn about the Google Cloud Storage Backend Provider](https://www.terraform.io/docs/backends/types/gcs.html)
- [Learn about Google Storage Bucket Resources in **terraform**](https://www.terraform.io/docs/providers/google/r/storage_bucket.html)


### Initializing Terraform

The following will initialize the local [terraform][tfhome] configuration without
creating a bucket for storing state data.

```sh
cd terraform
terraform init
```

Alternatively, after [creating a bucket in Google Cloud Storage](https://cloud.google.com/storage/docs/creating-buckets)
run the [terraform][tfhome] command defining `bucket` as the name of the bucket in Google Cloud Storage
and `prefix` as the name of the directory that will be created in that bucket. Configure [terraform][tfhome] to use
Google Cloud Storage by installing `gcs-bucket.tf` as shown.

> **Note:**
> The `bucket` and `prefix` variables help create what amounts to a filepath in Google Cloud Storage
> so be sure the names are unique.

```sh
cd terraform
cp ../ci/terraform/gcs-bucket.tf gcs-bucket.tf
terraform init --backend-config "bucket=<BUCKET_NAME>" --backend-config "prefix=<DIRECTORY_TO_CREATE_IN_BUCKET>"
```

> **Tip:**
> Strange errors when running `terraform init` may be the result of older
> configuration left over in a `.terraform` subdirectory in the current working
> directory. Remove or rename the directory to start with a clean slate.

### Configuration Variables for Terraform

[Terraform][tfhome] accepts variables which control its behaviors and the targets the
environment to build a cluster. Variables may be set through a
`terraform.tfvars` file or by setting environment variables.

The table below describes the variables and their names when set in the
environment versus their names in a `terraform.tfvars` file.

|Environment Variable Name|tfvars name|Type|Pipeline Visibility|Description|
|-|-|-|-|-|
|`TF_VAR_google_project`|`google_project`|Required|Secret|Google Project ID in GCP where resources will be provisioned.|
|`TF_VAR_google_zone`>|`google_zone`|Required|Secret|Regional zone where resources will be provisioned. [Default: us-central1-b]|
|`TF_VAR_prefix`|`prefix`|Required|Public|String prepended to resource names.|
|`TF_VAR_ssh_user`|`ssh_user`|Required|Public|User account allowed SSH access to resource.|
|`TF_VAR_ssh_public_key`|`ssh_public_key`|Required|Secret|Public ssh key associated with the user account defined in ssh_user.|
|`TF_VAR_consul_count`|`consul_count`|Optional|Public|Number of consul nodes to create. [Default: 3]|
|`TF_VAR_database_count`|`database_count`|Optional|Public|Number of database nodes to create. [Default: 3]|
|`TF_VAR_application_count`|`application_count`|Optional|Public|Number of application nodes to create. [Default: 1]|

Copy ***ONE*** of the following example files to the [terraform][tfhome] directory from
the [`examples`](examples/) subdirectory and modify to reflect the desired
environment setup:

- [`terraform.tfvars.example`](examples/terraform.tfvars.example)
    - A [magic file path that terraform will know about and use during execution](https://learn.hashicorp.com/terraform/getting-started/variables.html#from-a-file).
- [`terraform_env.sh.example`](examples/terraform_env.sh.example)
    - Must be sourced in the shell prior to running terraform
      ```
      . terraform_env.sh
      ```

### Configuring Google Cloud Authentication with Terraform

1. [Obtain a Google Cloud authentication key JSON file](https://www.terraform.io/docs/providers/google/getting_started.html#adding-credentials)
1. [Set environment variable to path of JSON file containing key](https://www.terraform.io/docs/providers/google/provider_reference.html#full-reference)

> **Caution:**
> The contents of the *JSON* keyfile should remain secret.

Setting anyone ***ONE*** of the following environment variables will work.

```sh
export GOOGLE_CREDENTIALS="<path_to_key.json>"
export GOOGLE_CLOUD_KEYFILE_JSON="<path_to_key.json>"
export GCLOUD_KEYFILE_JSON="<path_to_key.json>"
export GOOGLE_APPLICATION_CREDENTIALS="<path_to_key.json>"
```

### Running Terraform

Run the following to ensure ***terraform*** will only perform the expected
actions:

```sh
terraform plan
```

Run the following to apply the configuration to the target Google Cloud
environment:

```sh
terraform apply
```

### Tearing Down the Terraformed Cluster

Run the following to verify that ***terraform*** will only impact the expected
nodes and then tear down the cluster.

```sh
terraform plan
terraform destroy
```

[tfhome]: https://www.terraform.io
[tfgoogle]: https://www.terraform.io/docs/providers/google/index.html
