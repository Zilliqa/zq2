// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Shard is Ownable {
    uint64 public parentShard;
    uint16 public consensusTimeoutMs;

    constructor(uint64 parentId, uint16 consensusTimeout) {
        parentShard = parentId;
        consensusTimeoutMs = consensusTimeout;
    }

    function canValidate(address validator) public returns (bool) {
        // dummy
        return true;
    }
}

