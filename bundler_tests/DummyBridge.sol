// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {
    IEntryPointNonces,
    IPaymaster,
    IEntryPoint,
    PackedUserOperation,
    IAccount,
    IAccountExecute
} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {
    IERC7786GatewaySource,
    IERC7786Recipient
} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {CAIP2, CAIP10} from "@openzeppelin/contracts/utils/CAIP10.sol";

contract DummyBridge is
    Pausable,
    IERC7786GatewaySource,
    IEntryPointNonces,
    IPaymaster,
    IAccount
{
    uint nonce;
    mapping(address => mapping(uint192 => uint256)) public nonceSequenceNumber;

    event Received(bytes32 indexed receiveId, address gateway);
    IEntryPoint entryPoint;

    constructor(address _ep) payable {
        entryPoint = IEntryPoint(_ep);
    }

    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external {
        // 1. Validate the userOp

        // 2. Extract the call arguments
        bytes32 sendId = keccak256(userOp.callData);
        address gateway = address(uint160(userOp.nonce >> 96));
        address relayer = address(uint160(userOp.paymasterAndData));

        // Call the gateway
        bytes4 result = IERC7786Recipient(gateway).receiveMessage(
            sendId,
            relayer,
            userOp.callData
        );
        require(
            result == IERC7786Recipient.receiveMessage.selector,
            "Gateway.receiveMessage() failed"
        );
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32,
        uint256 missingWalletFunds
    ) public override returns (uint256 validationData) {
        // TODO: Check relayer signature
        validationData = 0;
    }

    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        // TODO: Check bls12-381 multi-signature
        context = "";
        validationData = 0;
    }

    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint
    ) external {
        // TODO: Record relayer/signers for rewards
    }

    receive() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

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

    /// Gateway's IERC7786Recipient::receiveMessage()
    ///
    /// The gateway will deconstruct the quad-tuple payload and send the original payload to its destination.
    function receiveMessage(
        bytes32 receiveId,
        bytes calldata relayer10, // CAIP10 - relayer address
        bytes calldata payload
    ) external payable returns (bytes4) {
        // 1. Validate caller
        // TODO: require(msg.sender == XXX)

        // 2. Record relayer
        address relayer = Strings.parseAddress(relayer10);
        emit Received(receiveId, relayer);

        // 3. Decode callData into its constituent parts
        (
            bytes memory sender,
            bytes memory recipient,
            bytes memory payload,
            uint256 nonce
        ) = abi.decode(userOp.callData, (bytes, bytes, bytes, uint256));

        // 4. Nonce replay check

        // 5. Send to destination
        (string memory dst_chain, string memory dst_addr) = CAIP10.parse(
            string(recipient)
        );
        require(dst_chain == CAIP2.local(), "Foreign destination");
        address destination = Strings.parseAddress(dst_addr);

        bytes4 result = IERC7786Recipient(destination).receiveMessage(
            receiveId,
            src_addr,
            payload
        );
        require(
            result == IERC7786Recipient.receiveMessage.selector,
            "Target failed"
        );
        return IERC7786Recipient.receiveMessage.selector;
    }

    function sendMessage(
        bytes calldata recipient, // CAIP10/EIP155 full address
        bytes calldata payload,
        bytes[] calldata attributes // Stick pricing in here?
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

        uint256 value =
            (uint256(max_priority_fee_per_gas) << 128) |
                uint256(max_fee_per_gas);

        bytes memory gateway = bytes(CAIP10.local(address(this)));

        emit MessageSent(
            sendId,
            gateway,
            recipient,
            wrappedPayload,
            value,
            attributes
        );
    }
}
