// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {
    IERC7786GatewaySource,
    IERC7786Recipient
} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {CAIP10} from "@openzeppelin/contracts/utils/CAIP10.sol";

contract DummyBridge is Pausable, IERC7786GatewaySource {
    uint nonce;

    constructor() {}

    function supportsAttribute(
        bytes4 /*selector*/
    ) public view virtual returns (bool) {
        return false;
    }

    function sendMessage(
        bytes calldata recipient, // Binary Interoperable Address
        bytes calldata payload,
        bytes[] calldata attributes
    ) public payable virtual whenNotPaused returns (bytes32 sendId) {
        bytes memory sender = bytes(CAIP10.local(msg.sender));

        // wrapping the payload
        bytes memory wrappedPayload = abi.encode(
            ++nonce,
            sender,
            recipient,
            payload
        );

        sendId = keccak256(wrappedPayload);

        emit MessageSent(
            sendId,
            sender,
            recipient,
            wrappedPayload,
            0, // TODO: gas/fees?
            attributes
        );
    }
}
