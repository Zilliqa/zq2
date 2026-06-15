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
import {NoncesKeyed} from "@openzeppelin/contracts/utils/NoncesKeyed.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

contract DummyBridge is
    Pausable,
    IERC7786GatewaySource,
    IERC7786Recipient,
    IEntryPointNonces,
    IPaymaster,
    IAccount,
    NoncesKeyed
{
    event MessageReceived(bytes32 indexed receiveId, address gateway);
    IEntryPoint entryPoint;

    bytes32 private immutable LOCAL_CHAIN_K256;
    address private EP_ADDRESS;

    mapping(uint64 => uint128[6]) private destinationFees;

    constructor(address _ep) payable {
        entryPoint = IEntryPoint(_ep);
        LOCAL_CHAIN_K256 = keccak256(
            InteroperableAddress.formatEvmV1(block.chainid)
        );
        EP_ADDRESS = _ep;

        // pre-populate
        destinationFees[uint64(block.chainid)] = [
            uint128(0x100001),
            uint128(0x100002),
            uint128(0x100003),
            uint128(0x100004),
            uint128(0x100005),
            uint128(0x100006)
        ];
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
        PackedUserOperation calldata,
        bytes32,
        uint256 missingWalletFunds
    ) public view override returns (uint256 validationData) {
        require(msg.sender == EP_ADDRESS, "Invalid entrypoint");
        require(missingWalletFunds == 0, "Missing paymaster");

        // TODO: Check relayer signature
        validationData = 0;
    }

    /// IPaymaster::validatePaymasterUserOp()
    /// Validates the multi-signature.
    function validatePaymasterUserOp(
        PackedUserOperation calldata,
        bytes32,
        uint256 maxCost
    ) external pure returns (bytes memory context, uint256 validationData) {
        require(maxCost > 0, "maxCost == 0");
        // address relayer = address(bytes20(userOp.paymasterAndData[:20]));

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
    ) public view virtual returns (uint128[6] memory) {
        return destinationFees[chain_id];
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
        emit MessageReceived(receiveId, relayer);

        // 3. Deconstruct the quad-tuple payload
        (
            bytes memory sender,
            bytes memory recipient,
            bytes memory payload,
            uint256 _nonce
        ) = abi.decode(_payload[4:], (bytes, bytes, bytes, uint256));
        // 4. Nonce replay check

        // 5. Send to destination
        (uint256 dst_chain, address dst_addr) = InteroperableAddress.parseEvmV1(
            recipient
        );
        require(
            keccak256(InteroperableAddress.formatEvmV1(dst_chain)) ==
                LOCAL_CHAIN_K256,
            "Foreign destination"
        );
        (uint256 src_chain, address src_addr) = InteroperableAddress.parseEvmV1(
            sender
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
        bytes calldata recipient, // ERC7930
        bytes calldata payload,
        bytes[] calldata // Stick pricing in here?
    ) public payable virtual whenNotPaused returns (bytes32 sendId) {
        (uint256 chainId, address addr) = InteroperableAddress.parseEvmV1(
            recipient
        ); // reverts if recipient is invalid

        // retrieve destination fee structure
        bytes[] memory attributes = new bytes[](1);
        bytes memory feeAttribute = abi.encodeWithSignature(
            "feeParams(uint128[6])",
            destinationFees[block.chainid]
        );
        attributes[0] = feeAttribute;

        // wrapping the payload
        bytes memory sender = InteroperableAddress.formatEvmV1(
            block.chainid,
            msg.sender
        );
        uint256 nonce = _useNonce(address(this), uint192(0));

        bytes memory wrappedPayload = abi.encodeWithSelector(
            IAccountExecute.executeUserOp.selector, // needed to trigger executeUserOp() later
            sender,
            recipient,
            payload,
            nonce
        );

        // compute sendId
        sendId = keccak256(wrappedPayload);

        bytes memory gateway = InteroperableAddress.formatEvmV1(
            block.chainid,
            address(this)
        );

        emit MessageSent(
            sendId,
            gateway,
            recipient,
            wrappedPayload,
            0,
            attributes
        );
    }
}
