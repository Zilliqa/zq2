// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.4;

import "./shard.sol";

contract ShardRegistry is Shard {
    event ShardAdded(uint id);
    event LinkAdded(uint from, uint indexed to);

    /// Tried to register a shard that is already registered
    error ShardAlreadyExists(uint id);
    error LinkSourceDoesntExist();
    error LinkTargetDoesntExist();
    error NotAuthorizedToLink();

    address[] shards;
    mapping(uint => uint) indices;

    mapping(uint => uint) links;

    // We construct this at genesis so we cannot know the genesis hash. Hence we pass 0.
    //
    // However, on the main shard, there is no higher source of trust to verify the genesis
    // than the chain itself (which also contains this contract), so this is not a problem.
    constructor(uint16 consensusTimeoutMs) Shard(block.chainid, block.chainid, consensusTimeoutMs, 0) {
        addShard(block.chainid, address(this));
    }

    function addShard(uint shardId, address shardContract) public {
        if (indices[shardId] != 0) {
            revert ShardAlreadyExists(shardId);
        }
        shards.push(shardContract);
        indices[shardId] = shards.length - 1;
        emit ShardAdded(shardId);
    }

    function addLink(uint sourceId, uint targetId) public {
        uint indexFrom = indices[sourceId];
        if (indexFrom == 0) {
            revert LinkSourceDoesntExist();
        }
        uint indexTo = indices[targetId];
        if (indexTo == 0) {
            revert LinkTargetDoesntExist();
        }

        if (msg.sender != shards[indexFrom]) {
            revert NotAuthorizedToLink();
        }

        links[sourceId] = targetId;
        emit LinkAdded(sourceId, targetId);
    }
}

