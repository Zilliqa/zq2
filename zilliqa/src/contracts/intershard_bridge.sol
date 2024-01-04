// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.4;

contract IntershardBridge {
    event Relayed(
        uint64 indexed targetChainId,
        address source,
        address target,
        bytes call,
        uint64 gasLimit,
        uint128 gasPrice,
        uint64 indexed nonce
    );

    // shard_id => nonce => is_dispatched
    mapping(uint64 => mapping(uint64 => bool)) public dispatched;
    uint64 public nonce;

    function bridge(
        uint64 targetShard,
        address target,
        bytes calldata call,
        uint64 gasLimit,
        uint128 gasPrice
    ) external returns (uint) {
        emit Relayed(targetShard, msg.sender, target, call, gasLimit, gasPrice, nonce);
        return nonce++;
    }

    function validateCallNonce(uint64 sourceShardId, uint64 callNonce) internal {
        if (dispatched[sourceShardId][callNonce]) {
            revert("Nonce already used.");
        }
        dispatched[sourceShardId][callNonce] = true;
    }
}
