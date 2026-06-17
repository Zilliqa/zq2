// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

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
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";

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
    ReentrancyGuardTransient,
    EIP712Upgradeable,
    IAccountExecute,
    Account
{
    using Address for address;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice One-time initializer called by the factory immediately after
     *         deploying the proxy.
     *
     * @param  signerAddr  Owner / signing key for this account.
     */
    function initialize(address signerAddr) external initializer {
        assert(signerAddr != address(0));

        __EIP712_init("UccbSender", "1");
        __ERC165_init();
    }

    /// Use v0.8 entrypoint only
    function entryPoint() public pure override returns (IEntryPoint) {
        return ERC4337Utils.ENTRYPOINT_V08;
    }

    /// Called by validateUserOp()
    function _rawSignatureValidation(
        bytes32 hash,
        bytes calldata // signature
    ) internal pure override returns (bool) {
        // TODO: Check signature
        return hash != 0x0;
    }

    /// Called by handleOps()
    function executeUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external {
        // TODO:
        // 1. Determine if it is a CALL or CONFIG
        // 2. On CONFIG, update the stakers; and
        // 3. update the Paymaster stakers.
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
    ) external onlyEntryPointOrSelf {
        entryPoint().withdrawTo(to, amount);
    }

    /// UUPSUpgradeable
    function _authorizeUpgrade(
        address /*newImplementation*/
    ) internal view override onlyEntryPointOrSelf {
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
    ) public view virtual override(ERC165Upgradeable) returns (bool) {
        return
            interfaceId == type(IAccountExecute).interfaceId ||
            interfaceId == type(IAccount).interfaceId ||
            interfaceId == type(IERC165).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
