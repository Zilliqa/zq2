// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

// Extremely simplistic.

contract ShardRegistry {
    address public selfShard;
    uint64 public mainShardId;

    mapping(uint64 => address) public shards;

    constructor(address selfShardContract) {
        selfShard = selfShardContract;
        mainShardId = block.chainid;
    }

    addShard(uint64 shardId, address contractLocation) {
        if (shardId == mainShardId || shards[shardId] == address(0)) {
            revert("Shard already exists.");
        }
        shards[shardId] = contractLocation;
    }
}

