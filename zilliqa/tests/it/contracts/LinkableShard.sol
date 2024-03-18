// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../../../src/contracts/shard.sol";
import "../../../src/contracts/shard_registry.sol";

contract LinkableShard is Shard {
    ShardRegistry registry;

    constructor(uint parentId, uint16 consensusTimeout, bytes32 genesisHash, address shardRegistry) Shard(parentId, consensusTimeout, genesisHash) {
        registry = ShardRegistry(shardRegistry);
    }

    function addLink(uint targetId) public {
        registry.addLink(block.chainid, targetId);
    }
}

