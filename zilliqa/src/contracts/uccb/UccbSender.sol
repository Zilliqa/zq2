// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {
    IEntryPoint,
    IAccount,
    IAccountExecute,
    PackedUserOperation
} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {AbstractSigner} from "@openzeppelin/contracts/utils/cryptography/signers/AbstractSigner.sol";
import {MultiSignerERC7913WeightedCheckpointedUpgradeable} from "./MultiSignerERC7913WeightedCheckpointedUpgradeable.sol";
import {UopTypes, IUccbSender} from "./Uccb.sol";

/**
 * @title  UccbSender
 * @notice ERC-4337 Sender contract built entirely on OpenZeppelin v5.6.x.
 *
 * @custom:oz-upgrades-unsafe-allow constructor
 */
contract UccbSender is
    Initializable,
    ERC165Upgradeable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardTransient,
    EIP712Upgradeable,
    MultiSignerERC7913WeightedCheckpointedUpgradeable,
    IAccountExecute,
    Account,
    IUccbSender
{
    using Address for address;
    using ERC4337Utils for PackedUserOperation;

    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice One-time initializer called by the factory immediately after
     *         deploying the proxy.
     */
    function initialize(address admin_) external initializer {
        __EIP712_init("UccbSender", "1");
        __AccessControl_init();
        __ERC165_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(WITHDRAWER_ROLE, admin_);
    }

    // ****** EXECUTION STAGE ******

    /**
     * Execution Shim
     *
     * Only callable by this contract itself so that try/catch can wrap a low-level call.
     * @param target    the contract address
     * @param data      the calldata passed to that contract
     */
    function _callExternal(
        address target,
        bytes calldata data
    ) external onlyEntryPointOrSelf {
        target.functionCall(data);
    }

    /**
     * Execution Shim
     *
     * Only callable by this contract itself so that try/catch can wrap a low-level call.
     * @param data      the calldata passed to that contract
     */
    function _updateEpoch(bytes calldata data) external onlyEntryPointOrSelf {
        uint256 count = data.length / 112;

        bytes[] memory signers = new bytes[](count);
        uint128[] memory weights = new uint128[](count);

        uint256 offset = 5;
        // each element is a G1 public key (96) + weight(16).
        for (uint256 i = 0; i < count; i++) {
            signers[i] = bytes(data[offset:offset + 96]);
            offset += 96;
            weights[i] = uint128(bytes16(data[offset:offset + 16]));
            offset += 16;
        }

        uint128 threshold = uint128(bytes16(data[offset:offset + 16]));
        uint48 effectiveBlock = uint48(
            uint64(bytes8(data[offset + 16:offset + 24]))
        );

        _scheduleSignerSet(signers, weights, threshold, effectiveBlock);
    }

    /**
     * Execution Pipeline
     *
     * Called by the EntryPoint after successful validateUserOp.
     * @param userOp the validated UserOp.
     */
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32
    ) external onlyEntryPoint {
        require(userOp.callData.length > 5, "Invalid length");
        UopTypes msgType = UopTypes(uint8(bytes1(userOp.callData[4])));

        if (msgType == UopTypes.Call) {
            require(userOp.callData.length > 32, "Invalid call()");
            address gateway = address(bytes20(userOp.callData[5:25]));
            // calls the external shim
            try this._callExternal(gateway, userOp.callData[25:]) {
                return;
            } catch (bytes memory reason) {
                // Re-revert with the original reason.
                assembly {
                    revert(add(reason, 32), mload(reason))
                }
            }
        }

        if (msgType == UopTypes.SetStaker) {
            require(userOp.callData.length % 112 == 29, "Invalid addStaker()");
            try this._updateEpoch(userOp.callData) {
                return;
            } catch (bytes memory reason) {
                // Re-revert with the original reason.
                assembly {
                    revert(add(reason, 32), mload(reason))
                }
            }
        }
    }

    /**
     * Validate the UserOp.
     *
     * Override the parent implementation to include nonce check.
     * Since we use a 192-bit parallel prefix, each nonce should have a 0 suffix.
     */
    function _validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        bytes calldata signature
    ) internal view override returns (uint256) {
        require(userOp.nonce & type(uint64).max == 0, "Invalid nonce");
        return
            _rawSignatureValidation(
                _signableUserOpHash(userOp, userOpHash),
                signature
            )
                ? ERC4337Utils.SIG_VALIDATION_SUCCESS
                : ERC4337Utils.SIG_VALIDATION_FAILED;
    }

    // ****** SIGNERS MANAGEMENT ******

    /**
     * Manual Signers Update
     *
     * Sets the set of signers, weights and threshold at an effective height.
     * This is used to manually update the signers, in the event it falls out of sync.
     *
     * @param signers   array of 96-byte G1 public keys
     * @param weights   array of corresponding stakes/weights
     * @param threshold the signers must exceed this threshold.
     * @param effective the height where this set of signers is effective.
     */
    function setSigners(
        bytes[] calldata signers,
        uint128[] calldata weights,
        uint128 threshold,
        uint48 effective
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _scheduleSignerSet(signers, weights, threshold, effective);
    }

    /**
     * Get a hash of the Signers data.
     *
     * Called by the Rust code to determine if a signers update is necessary.
     */
    function getSignersHash() external view returns (bytes32) {
        uint256 count = getSignerCount();
        bytes[] memory signers = getSigners(0, uint64(count));
        uint128 total = totalWeight();

        bytes32[] memory signerHashes = new bytes32[](signers.length);
        for (uint256 i = 0; i < signers.length; i++) {
            signerHashes[i] = keccak256(signers[i]);
        }
        bytes memory payload = abi.encodePacked(
            uint64(block.chainid),
            signerHashes,
            total
        );
        return keccak256(payload);
    }

    // ****** DEPOSIT/STAKE MANAGEMENT *******

    function depositTo() external payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    function balanceOf() external view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    function withdrawTo(
        address payable to,
        uint256 amount
    ) external onlyRole(WITHDRAWER_ROLE) {
        entryPoint().withdrawTo(to, amount);
    }

    function addStake(
        uint32 unstakeDelaySec
    ) external payable onlyRole(DEFAULT_ADMIN_ROLE) {
        entryPoint().addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockStake() external onlyRole(DEFAULT_ADMIN_ROLE) {
        entryPoint().unlockStake();
    }

    function withdrawStake(
        address payable to
    ) external onlyRole(WITHDRAWER_ROLE) nonReentrant {
        assert(to != address(0));
        entryPoint().withdrawStake(to);
    }

    // ****** BOILER-PLATE ******

    function _authorizeUpgrade(
        address /*newImplementation*/
    ) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function supportsInterface(
        bytes4 interfaceId
    )
        public
        view
        virtual
        override(ERC165Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        return
            interfaceId == type(IAccountExecute).interfaceId ||
            interfaceId == type(IAccount).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    receive() external payable virtual override {}

    // REQUIRED - UNUSED
    function supportsAttribute(bytes4) external pure returns (bool) {
        return false;
    }
}
