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
import {NoncesKeyed} from "@openzeppelin/contracts/utils/NoncesKeyed.sol";

contract DummyBridge is
    Pausable,
    IERC7786GatewaySource,
    IERC7786Recipient,
    IEntryPointNonces,
    IPaymaster,
    IAccount,
    NoncesKeyed
{
    event Received(bytes32 indexed receiveId, address gateway);
    IEntryPoint entryPoint;

    bytes32 private immutable LOCAL_CHAIN_K256;
    address private EP_ADDRESS;

    constructor(address _ep) payable {
        entryPoint = IEntryPoint(_ep);
        LOCAL_CHAIN_K256 = keccak256(bytes(CAIP2.local()));
        EP_ADDRESS = _ep;
    }

    /// @dev Restrict calls to the EntryPoint or the owner themselves
    modifier onlyEntryPointOrOwner() {
        require(
            msg.sender == EP_ADDRESS, // || msg.sender == owner,
            "SimpleAccount: not entryPoint or owner"
        );
        _;
    }

    /// IAccountExecute::executeUserOp()
    /// Called in the execution phase of UserOp handling.
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32 _userOpHash
    ) external onlyEntryPointOrOwner {
        // 1. Validate the userOp

        // 2. Extract the call arguments
        bytes32 sendId = keccak256(userOp.callData);
        address gateway = address(uint160(userOp.nonce >> 96)); // byte20 prefix with gateway address
        address relayer = address(bytes20(userOp.signature[:20])); // byte20 prefix with signer wallet

        // Call the gateway
        require(
            IERC7786Recipient(gateway).receiveMessage(
                sendId,
                abi.encodePacked(relayer),
                userOp.callData
            ) == IERC7786Recipient.receiveMessage.selector,
            "Gateway.receiveMessage() failed"
        );
    }

    /// IAccount::validateUserOp()
    /// Validates the signature.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingWalletFunds
    ) public override returns (uint256 validationData) {
        require(msg.sender == EP_ADDRESS, "Invalid entrypoint");
        require(missingWalletFunds == 0, "Missing paymaster");

        // TODO: Check relayer signature
        validationData = 0;
    }

    /// IPaymaster::validatePaymasterUserOp()
    /// Validates the multi-signature.
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) external returns (bytes memory context, uint256 validationData) {
        address relayer = address(bytes20(userOp.paymasterAndData[:20]));

        // TODO: Check bls12-381 multi-signature
        context = ""; // abi.encode(relayer); // trigger post-op
        validationData = 0;
    }

    /// IPaymaster::postOp()
    /// Records the relayer and co-signers.
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint
    ) external onlyEntryPointOrOwner {
        // TODO: Record relayer/signers for rewards
    }

    receive() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    function getNonce(
        address sender,
        uint192 key
    ) external view returns (uint256) {
        return nonces(sender, key);
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

    /// IERC7786Recipient::receiveMessage()
    /// Deconstruct the quad-tuple payload and send the original payload to its destination.
    function receiveMessage(
        bytes32 receiveId,
        bytes calldata _relayer, // CAIP10 - relayer address
        bytes calldata _payload
    ) external payable returns (bytes4) {
        // 1. Validate caller
        // TODO: require(msg.sender == XXX)

        // 2. Record relayer
        address relayer = address(bytes20(_relayer));
        emit Received(receiveId, relayer);

        // 3. Deconstruct the quad-tuple payload
        (
            bytes memory sender,
            bytes memory recipient,
            bytes memory payload,
            uint256 _nonce
        ) = abi.decode(_payload[4:], (bytes, bytes, bytes, uint256));
        // 4. Nonce replay check

        // 5. Send to destination
        (string memory dst_chain, string memory dst_addr) = CAIP10.parse(
            string(recipient)
        );
        require(
            keccak256(bytes(dst_chain)) == LOCAL_CHAIN_K256,
            "Foreign destination"
        );
        (string memory src_chain, string memory src_addr) = CAIP10.parse(
            string(sender)
        );

        // require(
        //     IERC7786Recipient(Strings.parseAddress(dst_addr)).receiveMessage(
        //         receiveId,
        //         bytes(src_addr),
        //         payload
        //     ) == IERC7786Recipient.receiveMessage.selector,
        //     "Target failed"
        // );
        return IERC7786Recipient.receiveMessage.selector;
    }

    /// IERC7786GatewaySource::sendMessage()
    /// Constructs the cross-chain quad-tuple payload to be relayed.
    function sendMessage(
        bytes calldata recipient, // CAIP10/EIP155 full address
        bytes calldata payload,
        bytes[] calldata attributes // Stick pricing in here?
    ) public payable virtual whenNotPaused returns (bytes32 sendId) {
        bytes memory sender = bytes(CAIP10.local(msg.sender));
        uint256 nonce = _useNonce(address(this), uint192(0));

        // wrapping the payload
        bytes memory wrappedPayload = abi.encodeWithSelector(
            IAccountExecute.executeUserOp.selector, // needed to trigger executeUserOp() later
            sender,
            recipient,
            payload,
            nonce
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
