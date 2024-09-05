# Changelog

## [Unreleased]

Unreleased changes.
- [#1304](https://github.com/Zilliqa/zq2/pull/1304): Implement the following APIs for querying DS blocks: `GetDSBlock`, `GetDSBlockVerbose`, `GetLatestDSBlock`, `GetCurrentDSComm`, `GetCurrentDSEpoch`, `DSBlockListing`, `GetDSBlockRate`,

- [#1372](https://github.com/Zilliqa/zq2/pull/1372): Fix `code_hash` calculation and state delta application for empty EVM contracts.

- [#1373](https://github.com/Zilliqa/zq2/pull/1373): Fix duplicated requests for blocks when a node connects to the network.

- [#1379](https://github.com/Zilliqa/zq2/pull/1379): Add `GetTxBlockRate` API to return the current transaction block rate.

- [#1369](https://github.com/Zilliqa/zq2/pull/1369): Global variables in EVM refer to the current and not to the parent block

- [#1389](https://github.com/Zilliqa/zq2/pull/1389): Implement `TxBlockListing` API endpoint to return a paginated list of blocks

- [#1390](https://github.com/Zilliqa/zq2/pull/1390): Implement `GetNumPeers` API endpoint to get the current number of peers


## [0.1.1] - 2024-08-14

- [#1290](https://github.com/Zilliqa/zq2/pull/1281): Fix over-eager clean up of votes which could cause votes for pending blocks to get lost.
- [#1285](https://github.com/Zilliqa/zq2/pull/1285): Use `libp2p-autonat` to automatically determine a node's public addresses.
- [#1281](https://github.com/Zilliqa/zq2/pull/1281): Emit an `ERROR` level log when a node panics.
- [#1174](https://github.com/Zilliqa/zq2/pull/1174): Limit the returned size of `GetSmartContractState` when the `state_rpc_limit` configuration is set.
- [#1304](https://github.com/Zilliqa/zq2/pull/1304): Implement DS block APIs by inventing placeholder blocks.

## [0.1.0] - 2024-08-01

Initial release of Zilliqa 2.

[unreleased]: https://github.com/zilliqa/zq2/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/zilliqa/zq2/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/zilliqa/zq2/releases/tag/v0.1.0
