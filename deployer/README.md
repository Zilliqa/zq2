# ZQ2 deployer

The `deployer` is the `zq2` to go tool for the basic network operations.

It allows us to upgrade `zq2` networks and perform Zilliqa 1.0 to Zilliqa 2.0 persistence conversions.

## How-to upgrade a ZQ2 network

Upgrade Zilliqa 2.0 on GCP requires you to:

 * Log in: `gcloud auth login --update-adc`
 *  Create the configuration for your network:

    To configure the `deployer`, you need to specify:

    - `zq2_network_name`: string - the network name of the Zilliqa 2.0 network you want to upgrade. This is the value you specified as the label `zq2-network` for your GCP VM. The `deployer` will select all the VMs with that label as the target for the upgrade.

    - `gcp_project`: string - the project ID where your network is running.

    - `gcs_binary_bucket`: string - the GCS bucket used to stage the Zilliqa 2.0 binaries. The `deployer` will build the binary for the specified version and save them in the given `gcs_binary_bucket`. Afterwards, it will connect VM by VM, download that binary, swap the `/zilliqa` with the one downloaded from the bucket before restarting the process.

    ```
    cargo run --release --bin deployer -- new <zq2_network_name> <gcp_project> <gcs_binary_bucket>
    ```

    Here an example of the generated configuration file, `<zq2_network_name>.toml`:

    ```toml
    name = "<zq2_network_name>"
    version = "main"
    gcp_project = "<gcp_project>"
    binary_bucket = "<gcp_binary_bucket>
    ```

 * Perform the upgrade by running: `cargo run --bin deployer -- upgrade <zq2_network_name>.toml`