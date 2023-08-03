// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract ShardPointer {
    address public shardAddress;
    constructor(address shard) {
        shardAddress = shard;
    }
}
