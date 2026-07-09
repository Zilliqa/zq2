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
import {IUccbGateway} from "./Uccb.sol";

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
    IERC7786GatewaySource,
    IUccbGateway
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

    // ****** FEE MANAGEMENT FUNCTIONS ******

    /*
     * The gateway contract stores a set of gas/fees for the User Op.
     * Changes to the gas/fees will need to be managed via these functions.
     */
    event FeesUpdated(uint64 indexed id, uint128[6] fees);

    /**
     * Set/Update the Fees
     *
     * Set or update the set of fees for a destination chain, effective immediately.
     * @param id    the chain-id for the destination chain.
     * @param fees  the array of fees
     */

    function setFees(
        uint64 id,
        uint128[6] calldata fees
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        GatewayStorage storage $ = _getStorage(); // Get data pointer
        $._fees[id] = fees;
        emit FeesUpdated(id, fees);
    }

    /**
     * List the Fees
     *
     * Called by ZQ2 nodes to retrieve the fee structure for a given chain.
     * @param id    the chain-id for the destination chain.
     */

    function getFees(uint64 id) external view returns (uint128[6] memory) {
        GatewayStorage storage $ = _getStorage(); // Get data pointer
        return $._fees[id];
    }

    /**
     * Delete the Fees
     *
     * Manual deletion of the fees for a given chain.
     * @param id    the chain-id for the destination chain.
     */

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
     *
     * @param erc7930Recipient  the full ERC7930 recipient address
     * @param payload           an arbitrary payload sent to the recipient.
     * @param attributes        ERC7985 attributes; none supported at the moment.
     */

    function sendMessage(
        bytes calldata erc7930Recipient, // ERC7930(recipient)
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
        assert(attributes.length == 0);

        // check format
        bytes memory counterpart = __extractChain(erc7930Recipient);

        // ERC7930(sender)
        bytes memory erc7930Sender = InteroperableAddress.formatEvmV1(
            block.chainid,
            msg.sender
        );

        uint256 nonce = _useNonce(address(this), uint192(0));

        bytes memory wrappedPayload = abi.encode(
            erc7930Sender, // ERC7985 original sender
            erc7930Recipient, // ERC7985 receipient
            payload, // arbitrary payload
            nonce // to mitigate replays
        );

        // TODO: Record the original message?
        // TODO: deliver local messages directly?

        return
            _sendMessageToCounterpart(counterpart, wrappedPayload, attributes);
    }

    /**
     * Bridge Mechanism
     *
     * Called internally from sendMessage().
     * This function emits the MessageSent() event that is picked up by the Rust code,
     * which triggers the signing-relaying-bundling pipeline.
     * @param chain     ERC7930 destination chain
     * @param payload   the wrapped quad-tuple payload
     * @param attr      ERC7985 set of attributes; none for now.
     */
    function _sendMessageToCounterpart(
        bytes memory chain,
        bytes memory payload,
        bytes[] memory attr
    ) internal override(CrosschainLinkedUpgradeable) returns (bytes32) {
        (, bytes memory counterpart) = getLink(chain);

        bytes memory originator = InteroperableAddress.formatEvmV1(
            block.chainid,
            address(this)
        );

        // FIXME: assert(!counterpart.equal(originator));

        bytes32 sendId = keccak256(payload);

        emit MessageSent(sendId, originator, counterpart, payload, 0, attr);

        return sendId;
    }

    /**
     * Process Received Message
     *
     * Called internally from ERC7786Recipient.receiveMessage().
     * This function is called internally after checking that the message came from an authorized sender.
     * We check that the message itself is valid and proceed to deliver the mesage to the external contract,
     * which must be registered as a RECEIVING_CONTRACT.
     * @param receiveId         the keccak256() value of the payload
     * @param relayer           the address of the ERC4337 sender.
     * @param wrappedPayload    the wrapped quad-tuple payload
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

        Address.functionCall(target, payload);
        originator = originator;
    }

    /**
     * Configure the Sender/Remote mapping.
     *
     * When a message is received, it will be checked against this mapping to determine if the Sender is
     * authorised to deliver messages from that counterpart originating chain/network.
     * @param sender         The local ERC4337 sender contract allowed to call this Gateway receiveMessage().
     * @param counterpart    The full ERC7930 address of the remote Gateway contract, where sendMessage() sends it.
     */
    function setLink(
        address sender,
        bytes memory counterpart
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setLink(sender, counterpart, true);
    }

    // HELPERS

    function supportsAttribute(bytes4) external pure override returns (bool) {
        // TODO: Support some ERC7985 attributes e.g. timeout
        return false;
    }

    function __extractChain(
        bytes memory erc7930
    ) private pure returns (bytes memory) {
        (bytes2 chainType, bytes memory chainReference, ) = erc7930.parseV1();
        return InteroperableAddress.formatV1(chainType, chainReference, "");
    }

    /**
     * Sweep accumulated message fees.
     *
     * This is only used in the event that fees are accidentally sent to this contract.
     */
    function sweep(
        address payable to
    ) external onlyRole(WITHDRAWER_ROLE) nonReentrant {
        require(to != address(0));
        to.sendValue(address(this).balance);
    }

    // ****** BOILER-PLATE ******

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _authorizeUpgrade(
        address /*newImplementation*/
    ) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

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
