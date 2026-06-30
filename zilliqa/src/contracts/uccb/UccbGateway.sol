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
    bytes32 public constant ORIGINATING_CONTRACT = keccak256(
        "ORIGINATING_CONTRACT"
    );
    bytes32 public constant RECEIVING_CONTRACT = keccak256(
        "RECEIVING_CONTRACT"
    );

    /// Emitted when an inbound message is successfully received.
    event MessageReceived(bytes32 indexed receiveId, address gateway);

    /**
     * @notice One-time proxy initializer.
     */
    function initialize(address admin_) external initializer {
        assert(admin_ != address(0));
        CrosschainLinkedUpgradeable.Link[] memory links_;

        __EIP712_init("UccbGateway", "1");
        __AccessControl_init();
        __Pausable_init();
        __CrosschainLinked_init(links_);
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

    /*
     * Fee Management Functions
     * ========================
     *
     * The gateway contract stores a set of gas/fees for the User Op.
     * Changes to the gas/fees will need to be managed via these functions.
     */

    event FeesUpdated(uint64 indexed id, uint128[6] fees);

    /// @custom:storage-location erc7201:zilliqa.storage.UccbGateway
    struct GatewayStorage {
        mapping(bytes32 => bool) _usedIds;
        mapping(uint64 => uint128[6]) _fees;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.storage.UccbGateway")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant GatewayStorageSlot =
        0x92031f62218d4a32004c55a85ae23890f7585155ae9d18edef0cbbb077fb9a00;

    function _getStorage() private pure returns (GatewayStorage storage $) {
        assembly {
            $.slot := GatewayStorageSlot
        }
    }

    /**
     * Set the fees
     */
    function setFees(
        uint64 id,
        uint128[6] calldata fees
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        GatewayStorage storage $ = _getStorage(); // Get data pointer
        $._fees[id] = fees;
        emit FeesUpdated(id, fees);
    }

    function getFees(uint64 id) external view returns (uint128[6] memory) {
        GatewayStorage storage $ = _getStorage(); // Get data pointer
        return $._fees[id];
    }

    function deleteFees(uint64 id) external onlyRole(DEFAULT_ADMIN_ROLE) {
        GatewayStorage storage $ = _getStorage(); // Get data pointer
        delete $._fees[id];
    }

    /**
     * Sending Message
     *
     * This function is called by all external contracts that wish to use the UCCB to
     * bridge calls to other chains/networks. The calling contract must be registered
     * as a ORIGINATING_CONTRACT.
     */
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
        onlyRole(ORIGINATING_CONTRACT) // only registered contracts
        returns (bytes32)
    {
        assert(payload.length != 0);
        assert(msg.value == 0);
        assert(attributes.length == 0);

        // check format
        bytes memory counterpart = __extractChain(recipient);

        // ERC7930(sender)
        bytes memory sender = InteroperableAddress.formatEvmV1(
            block.chainid,
            msg.sender
        );

        uint256 nonce = _useNonce(address(this), uint192(0));

        bytes memory wrappedPayload = abi.encode(
            MSG_VERSION,
            MSG_CALL,
            sender,
            recipient,
            payload,
            nonce
        );

        // TODO: Record the original message?
        // TODO: deliver local messages directly?

        return
            _sendMessageToCounterpart(counterpart, wrappedPayload, attributes);
    }

    /**
     * Bridge Mechanism
     *
     * This function emits the MessageSent() event that is picked up by the Rust code,
     * which triggers the signing-relaying-bundling pipeline.
     */
    function _sendMessageToCounterpart(
        bytes memory chain,
        bytes memory payload,
        bytes[] memory attributes
    ) internal override(CrosschainLinkedUpgradeable) returns (bytes32) {
        (, bytes memory counterpart) = getLink(chain);

        bytes memory originator = InteroperableAddress.formatEvmV1(
            block.chainid,
            address(this)
        );

        // FIXME: prevent loop-back
        // assert(!counterpart.equal(originator));

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

    /**
     * Process Received Message
     *
     * This function is called internally after checking that the message came from an authorized sender.
     * We check that the message itself is valid and proceed to deliver the mesage to the external contract,
     * which must be registered as a RECEIVING_CONTRACT.
     */
    function _processMessage(
        address, // ERC4337(sender),
        bytes32 receiveId,
        bytes calldata relayer,
        bytes calldata wrappedPayload
    ) internal override {
        // prevent replays
        require(receiveId == keccak256(wrappedPayload), "Invalid payload");
        GatewayStorage storage $ = _getStorage();
        require(!$._usedIds[receiveId], "Replayed message");
        $._usedIds[receiveId] = true;

        // signal received
        (, address senderAddr) = relayer.parseEvmV1();
        emit MessageReceived(receiveId, senderAddr);

        // Deconstruct the quad-tuple payload
        assert(wrappedPayload.length > 128);
        (
            uint8 version,
            bytes4 msgType,
            bytes memory originator,
            bytes memory receiver,
            bytes memory payload,

        ) = abi.decode(
                wrappedPayload,
                (uint8, bytes4, bytes, bytes, bytes, uint256)
            );
        assert(version == MSG_VERSION);
        assert(msgType == MSG_CALL);

        // pass-thru to registered target
        (, address target) = receiver.parseEvmV1();
        require(hasRole(RECEIVING_CONTRACT, target), "Unregistered receiver");

        // TODO: allow failed execution
        require(
            IERC7786Recipient(target).receiveMessage(
                receiveId,
                originator,
                payload
            ) == IERC7786Recipient.receiveMessage.selector,
            "Execution failure"
        );
    }

    /**
     * @notice Configure the Sender/Remote mapping.
     *
     * When a message is received, it will be checked against this mapping to determine if the Sender is
     * authorised to deliver messages from that counterpart originating chain/network.
     *
     * @param sender         The local ERC4337 sender contract allowed to call this Gateway.
     * @param counterpart    The full ERC7930 address of the remote Gateway contract.
     */
    function setLink(
        address sender,
        bytes memory counterpart
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setLink(sender, counterpart, true);
    }

    /* HELPERS */

    function supportsAttribute(bytes4) external pure override returns (bool) {
        // TODO: Support some ERC7985 attributes
        return false;
    }

    function __extractChain(
        bytes memory s
    ) private pure returns (bytes memory) {
        (bytes2 chainType, bytes memory chainReference, ) = s.parseV1();
        return InteroperableAddress.formatV1(chainType, chainReference, hex"");
    }

    /**
     * @notice Withdraw accumulated message fees.
     * This is only used in the event that fees are accidentally sent to this contract.
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
        address /*newImplementation*/
    ) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {
        // TODO: audit log
    }

    // Pausable
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @dev Advertises interfaces implemented by this contract.
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
