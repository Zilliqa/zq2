// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.4;

contract Shard {
    event ValidatorAdded(address validator);

    uint public parentShard;
    bytes32 genesis; 

    uint16 public consensusTimeoutMs;

    constructor(uint parentId, uint16 consensusTimeout, bytes32 genesisHash) {
        parentShard = parentId;
        consensusTimeoutMs = consensusTimeout;
        genesis = genesisHash;
    }

    function isMain() public view returns (bool) {
        return parentShard == block.chainid;
    }

    function addValidator(address validator) public returns (bool) {
        emit ValidatorAdded(validator);
        // dummy
        return true;
    }
}

