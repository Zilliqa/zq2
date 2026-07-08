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
    Account
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
     * @dev Execute a single arbitrary call.
     *      Called by the EntryPoint after successful validateUserOp.
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPointOrSelf nonReentrant {
        _execute(target, value, data);
    }

    /**
     * @dev Low-level call with revert bubbling.
     *      Uses Address.functionCallWithValue so reverts propagate correctly
     *      even when returndata is empty.
     */
    function _execute(
        address target,
        uint256 value,
        bytes memory data
    ) internal {
        // Address.functionCallWithValue reverts with the upstream reason on failure.
        // We catch it here to emit ExecutionFailure before re-reverting.
        try this._callExternal(target, value, data) {
            // emit ExecutionSuccess(target, value, data);
        } catch (bytes memory reason) {
            // emit ExecutionFailure(target, value, data, reason);
            // Re-revert with the original reason.
            assembly {
                revert(add(reason, 32), mload(reason))
            }
        }
    }

    /**
     * @dev External shim so try/catch can wrap a low-level call.
     *      Only callable by this contract itself (via _execute's try/catch).
     */
    function _callExternal(
        address target,
        uint256 value,
        bytes calldata data
    ) external {
        assert(msg.sender == address(this));
        Address.functionCallWithValue(target, data, value);
    }

    /**
     * @dev Used by the Rust pipeline to update stakers/stakes
     *      Called by the EntryPoint after successful validateUserOp.
     */
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32
    ) external onlyEntryPoint {
        require(userOp.callData.length % 56 == 16, "Invalid length");

        uint256 count = userOp.callData.length / 56;

        bytes[] memory signers = new bytes[](count);
        uint64[] memory weights = new uint64[](count);

        uint256 offset = 0;
        // each element is a G1 compressed public key(48) + weight(8).
        for (uint256 i = 0; i < count; i++) {
            signers[i] = bytes(userOp.callData[offset:offset + 48]);
            weights[i] = uint64(
                bytes8(userOp.callData[offset + 48:offset + 56])
            );
            offset += 56;
        }

        uint64 threshold = uint64(bytes8(userOp.callData[offset:offset + 8]));
        uint48 effectiveBlock = uint48(
            uint64(bytes8(userOp.callData[offset + 8:offset + 16]))
        );

        _scheduleSignerSet(signers, weights, threshold, effectiveBlock);
    }

    // ****** SIGNERS MANAGEMENT ******

    function setSigners(
        bytes[] calldata signers,
        uint64[] calldata weights,
        uint64 threshold,
        uint48 effectiveBlock
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _scheduleSignerSet(signers, weights, threshold, effectiveBlock);
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
