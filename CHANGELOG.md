# Changelog

## [Unreleased]

Unreleased changes.

## [0.1.1] - 2024-08-14

- [#1290](https://github.com/Zilliqa/zq2/pull/1281): Fix over-eager clean up of votes which could cause votes for pending blocks to get lost.
- [#1285](https://github.com/Zilliqa/zq2/pull/1285): Use `libp2p-autonat` to automatically determine a node's public addresses.
- [#1281](https://github.com/Zilliqa/zq2/pull/1281): Emit an `ERROR` level log when a node panics.
- [#1174](https://github.com/Zilliqa/zq2/pull/1174): Limit the returned size of `GetSmartContractState` when the `state_rpc_limit` configuration is set.

## [0.1.0] - 2024-08-01

Initial release of Zilliqa 2.

[unreleased]: https://github.com/zilliqa/zq2/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/zilliqa/zq2/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/zilliqa/zq2/releases/tag/v0.1.0
