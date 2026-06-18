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
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {NoncesKeyedUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/NoncesKeyedUpgradeable.sol";
import {IAccountExecute} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

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
 *    2. Calls receiveMessage on the registered IERC7786Recipient.
 *    3. Emits MessageReceived.
 *
 * @custom:oz-upgrades-unsafe-allow constructor
 */

contract UccbGateway is
    Initializable,
    CrosschainLinkedUpgradeable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardTransient,
    NoncesKeyedUpgradeable,
    EIP712Upgradeable,
    IERC7786GatewaySource
{
    using Address for address payable;
    // using SafeCast for uint256;
    using InteroperableAddress for bytes;
    using Bytes for bytes;

    // Roles
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// Emitted when an inbound message is successfully received.
    event MessageReceived(bytes32 indexed receiveId, address gateway);

    /**
     * @notice One-time proxy initializer.
     *
     * @param  admin_   Address granted DEFAULT_ADMIN_ROLE (and all sub-roles).
     * @param  links    Initial chain links (gateway ↔ counterpart pairs).
     *                  Each entry is a {CrosschainLinkedUpgradeable.Link} struct.
     */
    function initialize(
        address admin_,
        CrosschainLinkedUpgradeable.Link[] memory links
    ) external initializer {
        assert(admin_ != address(0));

        __EIP712_init("UccbGateway", "1");
        __AccessControl_init();
        __Pausable_init();
        __CrosschainLinked_init(links);
        __ERC165_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(WITHDRAWER_ROLE, admin_);
        _grantRole(PAUSER_ROLE, admin_);
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// CoDec
    uint8 internal constant MSG_VERSION = 1;
    bytes4 internal constant MSG_CALL = 0x1b8b921d; // call(address,bytes)
    bytes4 internal constant MSG_TRANSFER = 0xa9059cbb; // transfer(address,uint256)

    function _encode(
        bytes4 msgType,
        bytes memory body
    ) internal pure returns (bytes memory) {
        // TODO: Reduce size
        return
            abi.encodeWithSelector(
                IAccountExecute.executeUserOp.selector, // needed to trigger executeUserOp() later
                MSG_VERSION,
                msgType,
                body
            );
    }

    function _decode(
        bytes calldata payload
    ) internal pure returns (bytes4, bytes memory) {
        assert(payload.length >= 32);
        (uint8 version, bytes4 mType, bytes memory b) = abi.decode(
            payload[4:],
            (uint8, bytes4, bytes)
        );
        assert(version == MSG_VERSION);
        return (mType, b);
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
    ) external payable override whenNotPaused nonReentrant returns (bytes32) {
        assert(payload.length != 0);
        assert(msg.value == 0);
        assert(attributes.length == 0);

        // ERC7930(sender)
        bytes memory sender = InteroperableAddress.formatEvmV1(
            block.chainid,
            msg.sender
        );

        uint256 nonce = _useNonce(address(this), uint192(0));

        bytes memory wrappedPayload = _encode(
            MSG_CALL,
            abi.encode(sender, recipient, payload, nonce)
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

        bytes memory originator = InteroperableAddress.formatEvmV1(
            block.chainid,
            address(this)
        );

        bytes32 sendId = keccak256(payload);

        emit MessageSent(
            sendId,
            originator,
            counterpart,
            payload,
            0,
            attributes
        );

        return sendId;
    }

    function setLink(
        address sender,
        bytes memory counterpart,
        bool allowOverride
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
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
        (bytes4 msgType, bytes memory quadtuple) = _decode(wrappedPayload);
        require(msgType == MSG_CALL);
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
        bytes memory s
    ) private pure returns (bytes memory) {
        (bytes2 chainType, bytes memory chainReference, ) = s.parseV1();
        return InteroperableAddress.formatV1(chainType, chainReference, hex"");
    }

    /**
     * @notice Withdraw accumulated message fees.
     * @param  to  Recipient of the fees.
     */
    function withdrawTo(
        address payable to,
        uint256 amount
    ) external onlyRole(WITHDRAWER_ROLE) nonReentrant {
        require(to != address(0));
        to.sendValue(amount);
    }

    // UUPSUpgradeable

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {
        // TODO: audit log
    }

    // PausableUpgradeable – restricted entry points

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @dev Advertises all interfaces implemented by this contract.
     *      AccessControlUpgradeable already registers IAccessControl.
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(AccessControlUpgradeable) returns (bool) {
        return
            interfaceId == type(IERC7786GatewaySource).interfaceId ||
            interfaceId == type(IERC7786Recipient).interfaceId ||
            interfaceId == type(IERC165).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
