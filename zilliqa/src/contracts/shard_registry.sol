// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./shard_pointer.sol";

// Extremely simplistic.
contract ShardRegistry is ShardPointer {
    mapping(uint => address) public shards;

    constructor(address selfShardContract) ShardPointer(selfShardContract) {}

    function addShard(uint shardId, address contractLocation) public {
        if (shardId == block.chainid || shards[shardId] == address(0)) {
            revert("Shard already exists.");
        }
        shards[shardId] = contractLocation;
    }
}

