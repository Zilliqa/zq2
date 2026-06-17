// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {
    IPaymaster,
    PackedUserOperation
} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {IEntryPoint} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {Address} from "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title  Paymaster
 * @notice ERC-4337 Paymaster skeleton built entirely on OpenZeppelin v5.6.x.
 */
contract UccbPaymaster is
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    PausableUpgradeable,
    // EIP712Upgradeable,
    ReentrancyGuardTransient,
    IPaymaster
{
    // using SafeERC20     for IERC20;
    using Address for address payable;
    using ERC4337Utils for PackedUserOperation;

    /**
     * @dev Restricts a function to the trusted EntryPoint.
     *      validatePaymasterUserOp and postOp MUST only be called by it.
     */
    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint()));
        _;
    }

    /// Use v0.8 entrypoint only
    function entryPoint() private pure returns (IEntryPoint) {
        return ERC4337Utils.ENTRYPOINT_V08;
    }

    /**
     * @dev Permanently disables initializers on the bare implementation
     *      so it cannot be hijacked.
     * @custom:oz-upgrades-unsafe-allow constructor
     */
    constructor() {
        _disableInitializers();
    }

    // ── Initializer ──────────────────────────────────────────

    /**
     * @notice One-time initializer called by the factory through the proxy.
     */
    function initialize(
        address _admin,
        uint256 // _maxCostPerOp
    ) external initializer {
        assert(_admin != address(0));
        __Ownable_init(_admin);
        __Pausable_init();
    }

    /**
     * @notice Called by the EntryPoint during the verification loop.
     *         Must decide whether to sponsor this UserOp and return:
     *           - context: arbitrary bytes forwarded to postOp (may be empty)
     *           - validationData: packed (sigFailure | validUntil | validAfter)
     *                             via ERC4337Utils.packValidationData
     */
    function validatePaymasterUserOp(
        PackedUserOperation calldata, // userOp,
        bytes32, // userOpHash,
        uint256 // maxCost
    )
        external
        view
        override
        onlyEntryPoint
        whenNotPaused
        returns (bytes memory context, uint256 validationData)
    {
        // Context is for postOp bookkeeping.
        context = "";
        validationData = ERC4337Utils.packValidationData(true, 0, 0); // true, forever
    }

    /**
     * @notice Called by the EntryPoint after the UserOp executes (or after
     *         a failed execution attempt).
     */
    function postOp(
        PostOpMode, //mode,
        bytes calldata context,
        uint256, // actualGasCost,
        uint256 // actualUserOpFeePerGas
    ) external view override onlyEntryPoint {
        // Decode the sponsor mode that was stored in context.
        if (context.length == 0) return;
    }

    /**
     * @notice Deposit ETH into the EntryPoint so the paymaster can cover gas.
     *         Anyone can call; the EntryPoint credits the deposit to this contract.
     */
    function depositToEntryPoint() external payable nonReentrant {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice Withdraw ETH from the EntryPoint deposit back to this contract.
     * @param  amount  Wei to withdraw.
     */
    function withdrawFromEntryPoint(
        uint256 amount
    ) external onlyOwner nonReentrant {
        entryPoint().withdrawTo(payable(address(this)), amount);
    }

    /**
     * @notice View the current EntryPoint deposit balance.
     */
    function getDeposit() external view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * @notice Add stake to the EntryPoint for this paymaster.
     *
     * @dev    Paymasters that access global / non-sender-associated storage
     *         in validatePaymasterUserOp MUST be staked to avoid bundler
     *         rejection under ERC-7562 reputation rules.
     *
     * @param  unstakeDelaySec  Delay (seconds) before stake can be withdrawn.
     *                          Must meet the EntryPoint's minimum.
     */
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        entryPoint().addStake{value: msg.value}(unstakeDelaySec);
    }

    /**
     * @notice Initiate the stake unlock process.  After the unstake delay
     *         has elapsed, call {withdrawStake}.
     */
    function unlockStake() external onlyOwner {
        entryPoint().unlockStake();
    }

    /**
     * @notice Withdraw previously unlocked stake.
     * @param  to  Recipient of the returned ETH.
     */
    function withdrawStake(address payable to) external onlyOwner nonReentrant {
        assert(to != address(0));
        entryPoint().withdrawStake(to);
    }

    /**
     * @notice Pause the paymaster. validatePaymasterUserOp will revert
     *         while paused, preventing new ops from being sponsored.
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Resume normal operation.
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    function _authorizeUpgrade(
        address /*newImplementation*/
    ) internal view override onlyOwner {}

    /**
     * @dev Accept ETH (refunds from EntryPoint, direct top-ups, etc.).
     */
    receive() external payable {}
}
