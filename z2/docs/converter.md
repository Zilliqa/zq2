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
consensus.genesis_accounts = [ ["0xcca93a2e1169caf02e515203d1539cc3f390890a", "1000000000000000000000000"] ]
EOF
```

* run the conversion tool:
(It's a long running task, so you might want run it on a cloud vm and ensure
the session keeps running in case you got disconnected or/and want recover the
session later. Use `screen`)

```
screen -a
export Z2_CONVERTER=true
z2 converter convert <--convert-accounts|--convert-blocks> /my/dir/persistences/zq1 /my/dir/persistences/zq2 config.toml <secret key>
```

The secret key is for a single validator which will be assumed to have 64 ZIL staked, so that the network has a validator on startup.
This tool requires plenty of ram to convert both accounts and blocks in a single run. Therefore, it's possible to convert either accounts or blocks at once.