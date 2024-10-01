# Changelog

## [Unreleased]

Unreleased changes, in reverse chronological order. New entries are added at the top of this list.

- [#1534](https://github.com/Zilliqa/zq2/pull/1534): Accept `input` or `data` for transaction request payloads.
- [#1530](https://github.com/Zilliqa/zq2/pull/1530): State at checkpoint should contain current block data as well as parent block data
- [#1449](https://github.com/Zilliqa/zq2/pull/1449): Restructure how blocks are stored to prevent database inconsistencies.
- [#1472](https://github.com/Zilliqa/zq2/pull/1472): Add `GetTransactionsForTxBlockEx` API.
- [#1476](https://github.com/Zilliqa/zq2/pull/1476): Fix topic in EVM-encoded Scilla events.
- [#1474](https://github.com/Zilliqa/zq2/pull/1474): Fix reading `ByStr20` maps in Scilla via EVM.
- [#1469](https://github.com/Zilliqa/zq2/pull/1469): Calculate block state roots earlier to avoid database inconsistency.

## [0.3.1] - 2024-09-13

- [#1445](https://github.com/Zilliqa/zq2/pull/1445): Apply state changes from transactions atomically.
- [#1448](https://github.com/Zilliqa/zq2/pull/1448): Fail gracefully if we are unable to parse a gossipsub message.
- [#1423](https://github.com/Zilliqa/zq2/pull/1423): Fix invalid value returned by calling `_balance` in a scilla transition.

## [0.3.0] - 2024-09-12

- [#1403](https://github.com/Zilliqa/zq2/pull/1403): Add `GetTransactionRate` API.
- [#1359](https://github.com/Zilliqa/zq2/pull/1359): Add tool to convert ZQ1 persistence into a ZQ2 data directory.
- [#1419](https://github.com/Zilliqa/zq2/pull/1419): Nodes outside the consensus commitee will no longer vote for a new view if a proposal is missed.
- [#1393](https://github.com/Zilliqa/zq2/pull/1393): Begin assembling a block proposal before a supermajority of votes is received.

## [0.2.0] - 2024-09-05

- [#1358](https://github.com/Zilliqa/zq2/pull/1358): Support `_codehash` in Scilla contracts.
- [#1398](https://github.com/Zilliqa/zq2/pull/1398): Improve syncing reliability by retrying requests for blocks that never receive a response.
- [#1350](https://github.com/Zilliqa/zq2/pull/1350): Support `CHAINID`, `BLOCKNUMBER`, and `TIMESTAMP` in Scilla contracts.
- [#1390](https://github.com/Zilliqa/zq2/pull/1390): Implement `GetNumPeers` API endpoint to get the current number of peers.
- [#1391](https://github.com/Zilliqa/zq2/pull/1391): Change response type of `GetMinimumGasPrice` to a string.
- [#1389](https://github.com/Zilliqa/zq2/pull/1389): Implement `TxBlockListing` API endpoint to return a paginated list of blocks.
- [#1379](https://github.com/Zilliqa/zq2/pull/1379): Add `GetTxBlockRate` API to return the current transaction block rate.
- [#1369](https://github.com/Zilliqa/zq2/pull/1369): Global variables in EVM now refer to the current block, not the parent block.
- [#1373](https://github.com/Zilliqa/zq2/pull/1373): Fix duplicated requests for blocks when a node connects to the network.
- [#1372](https://github.com/Zilliqa/zq2/pull/1372): Fix `code_hash` calculation and state delta application for empty EVM contracts.
- [#1270](https://github.com/Zilliqa/zq2/pull/1270): Implement first half of `scilla_call` precompile for EVM->Scilla interop.
- [#1366](https://github.com/Zilliqa/zq2/pull/1366): Avoid failing if a checkpoint is configured and the node has already been started from that checkpoint.
- [#1356](https://github.com/Zilliqa/zq2/pull/1356): Accept bech32 addresses for some existing Zilliqa APIs.
- [#1304](https://github.com/Zilliqa/zq2/pull/1304): Implement the following APIs for querying DS blocks: `GetDSBlock`, `GetDSBlockVerbose`, `GetLatestDSBlock`, `GetCurrentDSComm`, `GetCurrentDSEpoch`, `DSBlockListing`, `GetDSBlockRate`.
- [#1334](https://github.com/Zilliqa/zq2/pull/1334): Avoid sleeping for unnecessarily long before proposing an empty block.
- [#1310](https://github.com/Zilliqa/zq2/pull/1310): Fix nodes trying to propose a block without any votes for that block.

## [0.1.1] - 2024-08-14

- [#1304](https://github.com/Zilliqa/zq2/pull/1304): Implement DS block APIs by inventing placeholder blocks.
- [#1290](https://github.com/Zilliqa/zq2/pull/1281): Fix over-eager clean up of votes which could cause votes for pending blocks to get lost.
- [#1285](https://github.com/Zilliqa/zq2/pull/1285): Use `libp2p-autonat` to automatically determine a node's public addresses.
- [#1281](https://github.com/Zilliqa/zq2/pull/1281): Emit an `ERROR` level log when a node panics.
- [#1174](https://github.com/Zilliqa/zq2/pull/1174): Limit the returned size of `GetSmartContractState` when the `state_rpc_limit` configuration is set.

## [0.1.0] - 2024-08-01

Initial release of Zilliqa 2.

[unreleased]: https://github.com/zilliqa/zq2/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/zilliqa/zq2/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/zilliqa/zq2/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/zilliqa/zq2/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/zilliqa/zq2/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/zilliqa/zq2/releases/tag/v0.1.0
