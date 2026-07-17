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
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";

/**
 * @title  Paymaster
 * @notice ERC-4337 Paymaster skeleton built entirely on OpenZeppelin v5.6.x.
 */
contract UccbPaymaster is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardTransient,
    IPaymaster
{
    // using SafeERC20     for IERC20;
    using Address for address payable;
    using ERC4337Utils for PackedUserOperation;

    // Roles
    bytes32 public constant SPONSORED_CONTRACT = keccak256(
        "SPONSORED_CONTRACT"
    );
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /**
     * @dev Restricts a function to the trusted EntryPoint.
     *      validatePaymasterUserOp and postOp MUST only be called by it.
     */
    modifier onlyEntryPoint() {
        require(msg.sender == address(entryPoint()), "Entrypoint only");
        _;
    }

    /// Use v0.9 entrypoint only
    function entryPoint() private pure returns (IEntryPoint) {
        return ERC4337Utils.ENTRYPOINT_V09;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // ── Initializer ──────────────────────────────────────────

    /**
     * @notice One-time initializer called by the factory through the proxy.
     */
    function initialize(address admin_) external initializer {
        assert(admin_ != address(0));

        __AccessControl_init();
        __Pausable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
        _grantRole(WITHDRAWER_ROLE, admin_);
        _grantRole(PAUSER_ROLE, admin_);
    }

    /**
     * @notice Called by the EntryPoint during the verification loop.
     *         Must decide whether to sponsor this UserOp and return:
     */
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32, // userOpHash,
        uint256 // maxCost
    )
        external
        view
        override
        onlyEntryPoint
        whenNotPaused
        returns (bytes memory, uint256)
    {
        // allow all from SENDER
        bool allowed = hasRole(SPONSORED_CONTRACT, userOp.sender);

        // Decode the signature
        require(userOp.signature.length == 328, "Not signature");

        // Slice out each segment and cast manually
        bytes memory signer = bytes(userOp.signature[0:96]);
        uint64 height = uint64(bytes8(userOp.signature[96:104]));
        bytes32 cosig = bytes32(userOp.signature[104:136]);

        // extract validUntil/validAfter
        // context = relayer + signers
        return (
            abi.encodePacked(height, cosig, signer),
            ERC4337Utils.packValidationData(allowed, 0, 0)
        ); // valid for 10-blocks
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
        // TODO: record the signer and co-signers
        if (context.length == 0) return;
    }

    // ****** DEPOSIT/STAKE MANAGEMENT *******

    function depositTo() external payable nonReentrant {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    function withdrawTo(
        uint256 amount
    ) external onlyRole(WITHDRAWER_ROLE) nonReentrant {
        entryPoint().withdrawTo(payable(address(this)), amount);
    }

    function balanceOf() external view returns (uint256) {
        return entryPoint().balanceOf(address(this));
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

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {
        newImplementation = newImplementation;
    }

    /**
     * @dev Accept ETH (refunds from EntryPoint, direct top-ups, etc.).
     */
    receive() external payable {}
}
