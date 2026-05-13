// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {IEntryPointNonces} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {CAIP10} from "@openzeppelin/contracts/utils/CAIP10.sol";

contract DummyBridge is Pausable, IERC7786GatewaySource, IEntryPointNonces {
    uint nonce;
    mapping(address => mapping(uint192 => uint256)) public nonceSequenceNumber;

    event Received(bytes32 indexed receiveId, address gateway);

    constructor() {}

    function getNonce(
        address sender,
        uint192 key
    ) external view returns (uint256) {
        return nonceSequenceNumber[sender][key] | (uint256(key) << 64);
    }

    function getFees(
        uint64 chain_id
    ) public view virtual returns (uint256 fees) {
        uint64 call_gas_limit = 0x200000;
        uint64 pre_verification_gas = 0x100000;
        uint64 verification_gas_limit = 0x300000;
        uint64 paymaster_verification_gas_limit = 0x400000;

        fees =
            (uint256(call_gas_limit) << 192) |
            (uint256(pre_verification_gas) << 128) |
            (uint256(verification_gas_limit) << 64) |
            uint256(paymaster_verification_gas_limit);
    }

    function supportsAttribute(
        bytes4 /*selector*/
    ) public view virtual returns (bool) {
        return false;
    }

    function receiveMessage(
        bytes32 receiveId,
        bytes calldata sender, // CAIP10
        bytes calldata payload
    ) external payable returns (bytes4) {
        (string memory chain, string memory addr) = CAIP10.parse(
            string(sender)
        );
        address gateway = Strings.parseAddress(addr);

        emit Received(receiveId, gateway);
        return IERC7786Recipient.receiveMessage.selector;
    }

    function sendMessage(
        bytes calldata recipient, // CAIP10
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

        uint128 max_fee_per_gas = 0x100000;
        uint128 max_priority_fee_per_gas = 1;

        sendId = keccak256(wrappedPayload);

        uint256 value = (uint256(max_priority_fee_per_gas) << 128) |
            uint256(max_fee_per_gas);

        bytes memory gw_sender = bytes(CAIP10.local(address(this)));

        emit MessageSent(
            sendId,
            gw_sender,
            recipient,
            wrappedPayload,
            value,
            attributes
        );
    }
}
