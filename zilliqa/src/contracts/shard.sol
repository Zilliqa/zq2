// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.4;

contract Shard {
    event ValidatorAdded(address validator);

    uint256 public id;
    uint256 public parentShard;
    bytes32 internal genesis;

    uint16 public consensusTimeoutMs;

    constructor(
        uint256 _id,
        uint256 parentId,
        uint16 consensusTimeout,
        bytes32 genesisHash
    ) {
        id = _id;
        parentShard = parentId;
        consensusTimeoutMs = consensusTimeout;
        genesis = genesisHash;
    }

    function isMain() public view returns (bool) {
        return parentShard == id;
    }

    function addValidator(address validator) public returns (bool) {
        emit ValidatorAdded(validator);
        // dummy
        return true;
    }
}
