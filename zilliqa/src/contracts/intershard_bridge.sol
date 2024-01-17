// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.4;

contract IntershardBridge {
    event Relayed(
        uint64 indexed targetChainId,
        address source,
        bool contract_creation,
        address target,
        bytes call,
        uint64 gasLimit,
        uint128 gasPrice
    );

    function bridge(
        uint64 targetShard,
        bool contract_creation,
        address target,
        bytes calldata call,
        uint64 gasLimit,
        uint128 gasPrice
    ) external {
        emit Relayed(targetShard, msg.sender, contract_creation, target, call, gasLimit, gasPrice);
    }
}
