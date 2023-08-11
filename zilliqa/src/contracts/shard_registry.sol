// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "./shard.sol";

contract ShardRegistry is Shard {
    event ShardAdded(uint id, address contractAddress);

    mapping(uint => address) shardContracts;
    uint[] shards;

    constructor(uint16 consensusTimeoutMs) Shard(block.chainid, consensusTimeoutMs) {
    }

    function addShard(uint shardId, address contractLocation) public {
        if (shardId == block.chainid || shardContracts[shardId] != address(0)) {
            revert("Shard already exists.");
        }
        shards.push(shardId);
        shardContracts[shardId] = contractLocation;
        emit ShardAdded(shardId, contractLocation);
    }
}

