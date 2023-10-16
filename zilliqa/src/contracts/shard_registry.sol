// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.4;

import "./shard.sol";

contract ShardRegistry is Shard {
    event ShardAdded(uint id);
    mapping(uint => uint) indices;
    address[] shards;

    constructor(uint16 consensusTimeoutMs) Shard(block.chainid, consensusTimeoutMs, 0) {
        addShard(block.chainid, address(this));
    }

    function addShard(uint shardId, address shardContract) public {
        if (indices[shardId] != 0) {
            revert("Shard was already registered.");
        }
        shards.push(shardContract);
        indices[shardId] = shards.length - 1;
        emit ShardAdded(shardId);
    }
}

