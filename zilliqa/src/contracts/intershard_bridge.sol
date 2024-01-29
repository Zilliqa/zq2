// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.4;

contract IntershardBridge {
    event Relayed(
        uint64 indexed targetChainId,
        address indexed source,
        bool contractCreation, // the order of this and target is important for ease of parsing
        address indexed target,
        uint64 sourceChainId,
        uint64 bridgeNonce,
        bytes call,
        uint64 gasLimit,
        uint128 gasPrice
    );

    uint64 nonce; // internal value used to guarantee transaction hash uniqueness

    function bridge(
        uint64 targetShard,
        address target, // not used if this is contractCreation = true
        bool contractCreation,
        bytes calldata call,
        uint64 gasLimit,
        uint128 gasPrice
    ) external {
        ++nonce;
        emit Relayed(targetShard, msg.sender, contractCreation, target, uint64(block.chainid), nonce, call, gasLimit, gasPrice);
    }
}
