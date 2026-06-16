// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    IERC7786GatewaySource,
    IERC7786Recipient
} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {CrosschainLinkedUpgradeable} from "@openzeppelin/contracts-upgradeable/crosschain/CrosschainLinkedUpgradeable.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {Bytes} from "@openzeppelin/contracts/utils/Bytes.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {NoncesKeyedUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/NoncesKeyedUpgradeable.sol";
import {IAccountExecute} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

/**
 * @title  PayloadCodec
 * @notice Encode and decode the application-level message envelope that
 *         travels as the `payload` field of an ERC-7786 message.
 *
 * @dev Envelope format (abi.encode):
 *
 *   ( uint8  version,      - codec version (currently 1)
 *     bytes4 msgType,      - application-defined message type selector
 *     bytes  body    )     - type-specific payload bytes
 *
 * Versioning the envelope at the codec level means the gateway can
 * support rolling upgrades without breaking in-flight messages.
 */
library PayloadCodec {
    bytes4 public constant MSG_CALL = 0x1b8b921d; // call(address,bytes)
    bytes4 public constant MSG_TRANSFER = 0xa9059cbb; // transfer(address,uint256)

    uint8 internal constant VERSION = 1;

    function encode(
        bytes4 msgType,
        bytes memory body
    ) internal pure returns (bytes memory) {
        return abi.encode(VERSION, msgType, body);
    }

    function decode(
        bytes calldata payload
    ) internal pure returns (bytes4 msgType, bytes memory body) {
        require(payload.length >= 32, "Payload too short");
        (uint8 version, bytes4 mType, bytes memory b) = abi.decode(
            payload,
            (uint8, bytes4, bytes)
        );
        require(version == VERSION, "Payload unsupported");
        return (mType, b);
    }
}

/**
 * @title  UccbGateway
 * @notice ERC-7786 gateway contract that implements both
 *         {IERC7786GatewaySource} and {IERC7786Recipient}.
 *
 *  OUTBOUND (source side):
 *    1. Application calls sendMessage(recipient, payload, attributes).
 *    2. Gateway validates, and assigns a sendId.
 *    3. Emits MessageSent. Off-chain relayers pick this up and relay
 *       the message to the destination chain gateway.
 *
 *  INBOUND (destination side / recipient side):
 *    1. Sender calls receiveMessage() with the cross-chain payload.
 *    2. Gateway verifies the relayer's RELAYER_ROLE attestation signature.
 *    3. Calls receiveMessage on the registered IERC7786Recipient.
 *    4. Emits MessageDelivered.
 *
 * @custom:oz-upgrades-unsafe-allow constructor
 */

contract UccbGateway is
    Initializable,
    CrosschainLinkedUpgradeable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardTransient,
    NoncesKeyedUpgradeable,
    IERC7786GatewaySource
{
    // using Address for address payable;
    // using SafeCast for uint256;
    using InteroperableAddress for bytes;
    using Bytes for bytes;

    /// Emitted when an inbound message is successfully received.
    event MessageReceived(bytes32 indexed receiveId, address gateway);

    /**
     * @notice One-time proxy initializer.
     *
     * @param  owner   Address granted DEFAULT_ADMIN_ROLE (and all sub-roles).
     * @param  links    Initial chain links (gateway ↔ counterpart pairs).
     *                  Each entry is a {CrosschainLinkedUpgradeable.Link} struct.
     */
    function initialize(
        address owner,
        CrosschainLinkedUpgradeable.Link[] memory links
    ) external initializer {
        require(owner != address(0), "Owner == 0");
        __Pausable_init();
        __CrosschainLinked_init(links);
        __Ownable_init(owner);
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // IERC7786GatewaySource
    function supportsAttribute(bytes4) external pure override returns (bool) {
        // TODO: Support some ERC7985 attributes
        return false;
    }

    // IERC7786GatewaySource
    function sendMessage(
        bytes calldata recipient, // ERC7930(recipient)
        bytes calldata payload,
        bytes[] calldata attributes
    )
        external
        payable
        override
        whenNotPaused
        nonReentrant
        returns (bytes32 sendId)
    {
        require(payload.length != 0, "Payload == 0");
        require(msg.value == 0, "Value != 0");
        require(attributes.length == 0, "Attributes != 0");

        // ERC7930(sender)
        bytes memory sender = InteroperableAddress.formatEvmV1(
            block.chainid,
            msg.sender
        );

        uint256 nonce = _useNonce(address(this), uint192(0));

        bytes memory wrappedPayload = abi.encodeWithSelector(
            IAccountExecute.executeUserOp.selector, // needed to trigger executeUserOp() later
            PayloadCodec.encode(
                PayloadCodec.MSG_CALL,
                abi.encode(sender, recipient, payload, nonce)
            )
        );

        // TODO: deliver local messages directly?

        return
            _sendMessageToCounterpart(
                __extractChain(recipient),
                wrappedPayload,
                attributes
            );
    }

    // CrosschainLinked
    function _sendMessageToCounterpart(
        bytes memory chain,
        bytes memory payload,
        bytes[] memory attributes
    ) internal override returns (bytes32) {
        (, bytes memory counterpart) = getLink(chain);

        bytes memory sender = InteroperableAddress.formatEvmV1(
            block.chainid,
            address(this)
        );

        bytes32 sendId = keccak256(payload);

        emit MessageSent(sendId, sender, counterpart, payload, 0, attributes);

        return sendId;
    }

    function setLink(
        address sender,
        bytes memory counterpart,
        bool allowOverride
    ) public onlyOwner {
        _setLink(sender, counterpart, allowOverride);
    }

    mapping(bytes32 => bool) private _usedIds;

    // ERC7786Recipient
    function _processMessage(
        address, // ERC4337(sender),
        bytes32 receiveId,
        bytes calldata relayer,
        bytes calldata wrappedPayload
    ) internal override {
        require(receiveId == keccak256(wrappedPayload), "Invalid payload");

        (, address senderAddr) = relayer.parseEvmV1();

        // Deconstruct the quad-tuple payload
        (bytes4 msgType, bytes memory quadtuple) = PayloadCodec.decode(
            wrappedPayload[4:]
        );
        require(msgType == PayloadCodec.MSG_CALL);
        (
            bytes memory sender,
            bytes memory recipient,
            bytes memory payload,

        ) = abi.decode(quadtuple, (bytes, bytes, bytes, uint256));

        // prevent replays
        require(!_usedIds[receiveId], "Already processed");
        _usedIds[receiveId] = true;

        // signal received
        emit MessageReceived(receiveId, senderAddr);

        // pass-thru to target
        (, address target) = recipient.parseEvmV1();
        // TODO: allow failed execution
        require(
            IERC7786Recipient(target).receiveMessage(
                receiveId,
                sender,
                payload
            ) == IERC7786Recipient.receiveMessage.selector,
            "Execution failure"
        );
    }

    // Helper
    function __extractChain(
        bytes memory self
    ) private pure returns (bytes memory) {
        (bytes2 chainType, bytes memory chainReference, ) = self.parseV1();
        return InteroperableAddress.formatV1(chainType, chainReference, hex"");
    }

    // UUPSUpgradeable

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    // PausableUpgradeable – restricted entry points

    function pause() external onlyOwner {
        _pause();
    }
    function unpause() external onlyOwner {
        _unpause();
    }
}
