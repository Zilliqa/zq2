// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// Extremely simplistic.
contract ShardRegistry {
    uint[] shards;

    constructor() {
        shards.push(123456789);
    }

    function addShard(uint shardId) public {
        if (shardId == block.chainid || shards[shardId] != address(0)) {
            revert("Shard already exists.");
        }
        shards[shardId] = contractLocation;
    }
}

