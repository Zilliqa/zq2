// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Account} from "@openzeppelin/contracts/account/Account.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {
    IEntryPoint,
    IAccountExecute,
    PackedUserOperation
} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title  UccbSmartAccount
 * @notice ERC-4337 Sender contract built entirely on OpenZeppelin v5.6.x.
 *
 * @custom:oz-upgrades-unsafe-allow constructor
 */
contract UccbSmartAccount is
    Initializable,
    // SignerECDSAUpgradeable,
    // ERC7739Upgradeable,
    // ERC165Upgradeable,
    UUPSUpgradeable,
    ReentrancyGuardTransient,
    // IERC721Receiver,
    // IERC1155Receiver
    IAccountExecute,
    Account
{
    using Address for address;

    /**
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @notice One-time initializer called by the factory immediately after
     *         deploying the proxy.
     *
     * @param  signerAddr  Owner / signing key for this account.
     *
     * UUPSUpgradeable and ReentrancyGuardTransient have no state to init.
     */
    function initialize(address signerAddr) external initializer {
        assert(signerAddr != address(0));
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
    ) external {}

    /**
     * @notice Top-up this account's gas deposit in the EntryPoint.
     */
    function addDeposit() external payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice View current EntryPoint deposit balance.
     */
    function getDeposit() external view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * @notice Withdraw ETH from the EntryPoint deposit.
     * @param  to      Recipient.
     * @param  amount  Amount to withdraw (in wei).
     */
    function withdrawDepositTo(
        address payable to,
        uint256 amount
    ) external onlyEntryPointOrSelf {
        entryPoint().withdrawTo(to, amount);
    }

    /// UUPSUpgradeable
    function _authorizeUpgrade(
        address /*newImplementation*/
    ) internal view override onlyEntryPointOrSelf {}

    /**
     * @dev Account.receive() already exists and emits nothing.
     *      Override to emit an event so indexers can track deposits.
     */
    // receive() external payable virtual override {
    //     emit Received(msg.sender, msg.value);
    // }
}
