// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.4;

import "./shard.sol";

contract ShardRegistry is Shard {
    event ShardAdded(uint id);
    mapping(uint => uint) indices;
    address[] shards;

    // We construct this at genesis so we cannot know the genesis hash. Hence we pass 0.
    //
    // However, on the main shard, there is no higher source of trust to verify the genesis
    // than the chain itself (which also contains this contract), so this is not a problem.
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

