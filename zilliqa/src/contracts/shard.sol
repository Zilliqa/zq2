// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract Shard {
    uint public parentShard;
    uint16 public consensusTimeoutMs;

    constructor(uint parentId, uint16 consensusTimeout) {
        parentShard = parentId;
        consensusTimeoutMs = consensusTimeout;
    }

    function canValidate(address validator) public returns (bool) {
        // dummy
        return true;
    }
}

