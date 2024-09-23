// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../../src/contracts/shard.sol";
import "../../../src/contracts/shard_registry.sol";

contract LinkableShard is Shard {
    ShardRegistry registry;

    constructor(
        uint _id,
        uint parentId,
        uint16 consensusTimeout,
        bytes32 genesisHash,
        address shardRegistry
    ) Shard(_id, parentId, consensusTimeout, genesisHash) {
        registry = ShardRegistry(shardRegistry);
    }

    function addLink(uint targetId) public {
        registry.addLink(id, targetId);
    }
}
