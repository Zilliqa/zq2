# Zilliqa 2.0 - The next evolution of Zilliqa

## Running a Node

To start a node you need to pass a private key as a command line parameter.
This will be interpreted as both a BLS private key and a libp2p secp256k1 private key (of course the corresponding public keys will be different).

You will need to start at least 4 nodes before the network will begin to make progress.

### Example invocations for a network with 4 nodes

Note: You must include the public key and peer ID of one of the nodes in the config with the argument `-c`

```
cargo run --bin zilliqa -- 65d7f4da9bedc8fb79cbf6722342960bbdfb9759bc0d9e3fb4989e831ccbc227 -c ./infra/config.toml
cargo run --bin zilliqa -- 62070b1a3b5b30236e43b4f1bfd617e1af7474635558314d46127a708b9d302e  -c ./infra/config_rpc_disabled.toml
cargo run --bin zilliqa -- 56d7a450d75c6ba2706ef71da6ca80143ec4971add9c44d7d129a12fa7d3a364 -c ./infra/config_rpc_disabled.toml
cargo run --bin zilliqa -- db670cbff28f4b15297d03fafdab8f5303d68b7591bd59e31eaef215dd0f246a -c ./infra/config_rpc_disabled.toml
```

You may also want to set `RUST_LOG=zilliqa=trace` to see the most detailed level of logs.

### Bootstrap with docker-compose

Automated bootstrap of a 4 nodes Zilliqa 2.0 aka zq2 network.

Build the images first:

```bash
docker build . -t zq2-node0
```

Then run:

```bash
docker-compose up
```

## Testing

The tests can be run with `cargo test`.
Most tests create an in-memory network of nodes, with the libp2p networking layer stubbed out and send API requests to
the network.

Some tests involve compiling Solidity code.
`svm-rs` will automatically download and use a suitable version for your platform when you run these tests.

## Supported APIs

If an API is not mentioned in this table, support for it is not planned.
Please open an issue or PR for APIs that you think should be included.

🟢 = Fully supported

🟠 = Partially implemented, full support planned

🔴 = Not yet implemented, full support planned

| Method                                    | Status                                          |
| ----------------------------------------- | ----------------------------------------------- |
| `erigon_getHeaderByNumber`                | 🟢                                              |
| `eth_accounts`                            | 🟢                                              |
| `eth_blockNumber`                         | 🟢                                              |
| `eth_call`                                | 🟢                                              |
| `eth_chainId`                             | 🟢                                              |
| `eth_estimateGas`                         | 🟢                                              |
| `eth_gasPrice`                            | 🟢                                              |
| `eth_getBalance`                          | 🟢                                              |
| `eth_getBlockByHash`                      | 🟠 (<https://github.com/Zilliqa/zq2/issues/79>) |
| `eth_getBlockByNumber`                    | 🟠 (<https://github.com/Zilliqa/zq2/issues/79>) |
| `eth_getBlockTransactionCountByHash`      | 🟢                                              |
| `eth_getBlockTransactionCountByNumber`    | 🟢                                              |
| `eth_getCode`                             | 🟢                                              |
| `eth_getFilterChanges`                    | 🔴                                              |
| `eth_getFilterLogs`                       | 🔴                                              |
| `eth_getLogs`                             | 🟢                                              |
| `eth_getStorageAt`                        | 🟢                                              |
| `eth_getTransactionByBlockHashAndIndex`   | 🟢                                              |
| `eth_getTransactionByBlockNumberAndIndex` | 🟢                                              |
| `eth_getTransactionByHash`                | 🟢                                              |
| `eth_getTransactionCount`                 | 🟢                                              |
| `eth_getTransactionReceipt`               | 🟢                                              |
| `eth_getUncleByBlockHashAndIndex`         | 🟢                                              |
| `eth_getUncleByBlockNumberAndIndex`       | 🟢                                              |
| `eth_getUncleCountByBlockHash`            | 🟢                                              |
| `eth_getUncleCountByBlockNumber`          | 🟢                                              |
| `eth_newFilter`                           | 🔴                                              |
| `eth_newBlockFilter`                      | 🔴                                              |
| `eth_newPendingTransactionFilter`         | 🔴                                              |
| `eth_sendRawTransaction`                  | 🟢                                              |
| `eth_syncing`                             | 🟠                                              |
| `eth_uninstallFilter`                     | 🔴                                              |
| `net_listening`                           | 🟢                                              |
| `net_peerCount`                           | 🟠                                              |
| `net_version`                             | 🟢                                              |
| `ots_getApiLevel`                         | 🟢                                              |
| `ots_getBlockDetails`                     | 🟢                                              |
| `ots_getBlockDetailsByHash`               | 🟢                                              |
| `ots_getBlockTransactions`                | 🟢                                              |
| `ots_getContractCreator`                  | 🟢                                              |
| `ots_getInternalOperations`               | 🔴                                              |
| `ots_getTransactionBySenderAndNonce`      | 🔴                                              |
| `ots_getTransactionError`                 | 🟢                                              |
| `ots_hasCode`                             | 🟢                                              |
| `ots_searchTransactionsAfter`             | 🟢                                              |
| `ots_searchTransactionsBefore`            | 🟢                                              |
| `ots_traceTransaction`                    | 🟢                                              |
| `web3_clientVersion`                      | 🟢                                              |
| `web3_sha3`                               | 🟢                                              |
| `GetCurrentMiniEpoch`                     | 🟢                                              |
| `GetCurrentDSEpoch`                       | 🔴                                              |
| `GetNodeType`                             | 🔴                                              |
| `GetNetworkId`                            | 🟢                                              |
| `CreateTransaction`                       | 🟢                                              |
| `GetTransaction`                          | 🟢                                              |
| `GetSoftConfirmedTransaction`             | 🔴                                              |
| `GetDsBlock`                              | 🔴                                              |
| `GetDsBlockVerbose`                       | 🔴                                              |
| `GetTxBlock`                              | 🟠 (<https://github.com/Zilliqa/zq2/issues/79>) |
| `GetTxBlockVerbose`                       | 🟠 (<https://github.com/Zilliqa/zq2/issues/79>) |
| `GetLatestDsBlock`                        | 🔴                                              |
| `GetLatestTxBlock`                        | 🟢                                              |
| `GetBalance`                              | 🟢                                              |
| `GetMinimumGasPrice`                      | 🟢                                              |
| `GetPrevDSDifficulty`                     | 🔴                                              |
| `GetPrevDifficulty`                       | 🔴                                              |
| `GetSmartContracts`                       | 🔴                                              |
| `GetContractAddressFromTransactionID`     | 🟢                                              |
| `GetNumPeers`                             | 🔴                                              |
| `GetNumTxBlocks`                          | 🟢                                              |
| `GetNumDSBlocks`                          | 🔴                                              |
| `GetNumTransactions`                      | 🔴                                              |
| `GetTransactionRate`                      | 🔴                                              |
| `GetTxBlockRate`                          | 🔴                                              |
| `GetDSBlockRate`                          | 🔴                                              |
| `GetShardMembers`                         | 🔴                                              |
| `GetCurrentDSComm`                        | 🔴                                              |
| `DSBlockListing`                          | 🔴                                              |
| `TxBlockListing`                          | 🔴                                              |
| `GetBlockchainInfo`                       | 🔴                                              |
| `GetRecentTransactions`                   | 🔴                                              |
| `GetShardingStructure`                    | 🔴                                              |
| `GetNumTxnsTxEpoch`                       | 🔴                                              |
| `GetNumTxnsDSEpoch`                       | 🔴                                              |
| `GetSmartContractSubState`                | 🔴                                              |
| `GetSmartContractState`                   | 🟢                                              |
| `GetSmartContractCode`                    | 🟢                                              |
| `GetSmartContractInit`                    | 🟢                                              |
| `GetTransactionsForTxBlock`               | 🟢                                              |
| `GetTransactionsForTxBlockEx`             | 🔴                                              |
| `GetTotalCoinSupply`                      | 🔴                                              |
| `GetTotalCoinSupplyAsInt`                 | 🔴                                              |
| `GetPendingTxns`                          | 🔴                                              |
| `GetMinerInfo`                            | 🔴                                              |
| `GetTxnBodiesForTxBlock`                  | 🔴                                              |
| `GetTxnBodiesForTxBlockEx`                | 🔴                                              |
| `GetTransactionStatus`                    | 🔴                                              |
| `GetStateProof`                           | 🔴                                              |
| `GetVersion`                              | 🟢                                              |
| `GetRawDSBlock`                           | 🔴                                              |
| `GetRawTxBlock`                           | 🔴                                              |
