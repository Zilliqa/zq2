// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/Ownable.sol";

contract Shard is Ownable {
    uint64 public parentShard;

    constructor(uint64 parentId) {
        parentShard = parentId;
    }
}

