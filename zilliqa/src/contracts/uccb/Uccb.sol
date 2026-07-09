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
