// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Shard {
    event ValidatorAdded(address validator);

    uint public parentShard;
    uint16 public consensusTimeoutMs;

    constructor(uint parentId, uint16 consensusTimeout) {
        parentShard = parentId;
        consensusTimeoutMs = consensusTimeout;
    }

    function isMain() public view returns (bool) {
        return parentShard == block.chainid;
    }

    function addValidator(address validator) public returns (bool) {
        // dummy
        emit ValidatorAdded(validator);
        return true;
    }
}

