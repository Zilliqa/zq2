// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {AbstractSigner} from "@openzeppelin/contracts/utils/cryptography/signers/AbstractSigner.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {IEntryPoint, IAccount, IAccountExecute, PackedUserOperation} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {MultiSignerERC7913Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/signers/MultiSignerERC7913Upgradeable.sol";

// import {MultiSignerERC7913WeightedUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/signers/MultiSignerERC7913WeightedUpgradeable.sol";

/**
 * @title  UccbSender
 * @notice ERC-4337 Sender contract built entirely on OpenZeppelin v5.6.x.
 *
 * @custom:oz-upgrades-unsafe-allow constructor
 */
contract UccbSender is
    Initializable,
    MultiSignerERC7913Upgradeable,
    ERC165Upgradeable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    ReentrancyGuardTransient,
    EIP712Upgradeable,
    IAccountExecute,
    Account
{
    using Address for address;

    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice One-time initializer called by the factory immediately after
     *         deploying the proxy.
     *
     * @param  signers  Owner / signing key for this account.
     */
    function initialize(
        address admin_,
        bytes[] memory signers,
        uint64 threshold
    ) external initializer {
        __EIP712_init("UccbSender", "1");
        __AccessControl_init();
        __ERC165_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(WITHDRAWER_ROLE, admin_);

        // _addSigners(signers);
        // _setThreshold(uint64(1)); // one signer will pass
    }

    /// ***** External execution *****

    /**
     * @notice Execute a single arbitrary call.
     *         Called by the EntryPoint after successful validateUserOp.
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

    /// ***** Internal execution *****
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external {
        // TODO: Update stakers
    }

    /// Called by entrypoint
    function _rawSignatureValidation(
        bytes32 hash,
        bytes calldata signature
    )
        internal
        pure
        override(AbstractSigner, MultiSignerERC7913Upgradeable)
        returns (bool)
    {
        // TODO: verify all signatures signature
        return hash != 0 && signature.length != 0;
    }

    // ***** SIGNERS MANAGEMENT *****

    function addSigners(
        bytes[] memory signers
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _addSigners(signers);
    }

    function removeSigners(
        bytes[] memory signers
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _removeSigners(signers);
    }

    function setThreshold(
        uint64 threshold
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _setThreshold(threshold);
    }

    // ***** ENTRYPOINT *****

    function entryPoint() public pure override returns (IEntryPoint) {
        return ERC4337Utils.ENTRYPOINT_V08;
    }

    /**
     * @notice Top-up this account's gas deposit in the EntryPoint.
     */
    function depositTo() external payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice View current EntryPoint deposit balance.
     */
    function balanceOf() external view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * @notice Withdraw ETH from the EntryPoint deposit.
     * @param  to      Recipient.
     * @param  amount  Amount to withdraw (in wei).
     */
    function withdrawTo(
        address payable to,
        uint256 amount
    ) external onlyRole(WITHDRAWER_ROLE) {
        entryPoint().withdrawTo(to, amount);
    }

    // ***** BOILER-PLATE *****

    function _authorizeUpgrade(
        address /*newImplementation*/
    ) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {
        // TODO: audit log
    }

    /**
     * @dev Account.receive() already exists and emits nothing.
     *      Override to emit an event so indexers can track deposits.
     */
    receive() external payable virtual override {
        // emit Received(msg.sender, msg.value);
    }

    /**
     * @dev Advertises every interface this account satisfies.
     *      ERC165Upgradeable handles IERC165; all others are added here.
     */
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
}
