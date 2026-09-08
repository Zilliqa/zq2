// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
enum UopTypes {
    Call,
    Transfer,
    SetStaker
}

interface IUccbGateway {
    /// Emitted when an inbound message is successfully received.
    event MessageReceived(bytes32 indexed receiveId, address gateway);

    function getFees(uint64 id) external view returns (uint128[6] memory);
}

interface IUccbSender {
    /// Sets the internal signers data.
    function setSigners(
        bytes[] calldata signers,
        uint128[] calldata weights,
        uint128 threshold,
        uint48 effective
    ) external;

    /// Returns a Keccak256 hash of the internal signers data; useful for detecting changes
    function getSignersHash() external view returns (bytes32);
}
