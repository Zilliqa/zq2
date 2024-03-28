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

## ZQ1 to ZQ2 conversion how-to

* Log in: `gcloud auth login --update-adc`
* download the latest testnet or mainnet persistence:

  - GCS mainnet persistence backup: gs://zq1-mainnet-persistence/persistence
  - GCS mainnet blockchain data: gs://- zq1-mainnet-persistence/blockchain-data
  - GCS testnet persistence backup: gs://- zq1-testnet-persistence/persistence
  - GCS testnet blockchain data: gs://- zq1-testnet-persistence/blockchain-data
  
  ```
  mkdir -p /my/dir/persistences/zq1
  cd /my/dir/persistences/zq1
  gsutil cp gs://zq1-<network>-persistence/persistence/<network-name>-<blocknum>.tar.gz .
  gsutil cp gs://zq1-testnet-persistence/blockchain-data/<network-name>/<network-name>.tar.gz .
  ```
* extract the persistence and the blockchain data:
```
  tar xf <network-name>-<blocknum>.tar.gz
  tar xf <network-name>.tar.gz

  rm -f <network-name>-<blocknum>.tar.gz <network-name>.tar.gz
```

* create a sample configuration for the deployment tools. You only need the right chain-id (testnet: `33101`, mainnet: `32769`):
  ___Testnet example___
``` 
  cd /my/dir/zq2

  cat > config.toml <<-EOF
p2p_port = 3333
bootstrap_address = [ "12D3KooWNYaasyfY1wFrSHga3WBdZkb7bGhQiUz9926bQvk4HQj2", "/ip4/10.40.5.16/tcp/3333" ]

[[nodes]]
eth_chain_id = 33101 # change the chain it for your conversion
allowed_timestamp_skew = { secs = 60, nanos = 0 }
data_dir = "/data"
consensus.consensus_timeout = { secs = 60, nanos = 0 }
consensus.genesis_committee = [ ["a8b48d731061d1d7387cf113c96d9c2693e4442b91a8cf933037fe4b15f8977e4bc3afc4ed118d35a5181c05fb7e18be", "12D3KooWNYaasyfY1wFrSHga3WBdZkb7bGhQiUz9926bQvk4HQj2"] ]
consensus.genesis_accounts = [ ["0xcca93a2e1169caf02e515203d1539cc3f390890a", "1000000000000000000000000"] ]
EOF
```

* run the conversion tool:
(It's a long running task, so you might want run it on a cloud vm and ensure
the session keeps running in case you got disconnected or/and want recover the
session later. Use `screen`)

```
screen -a

cargo run --bin deployer --release -- convert-persistence /my/dir/persistences/zq1 /my/dir/persistences/zq2 config.toml
```
