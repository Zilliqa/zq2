// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {
    IEntryPoint,
    IAggregator,
    PackedUserOperation
} from "@openzeppelin/contracts/interfaces/draft-IERC4337.sol";
import {ERC4337Utils} from "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ERC165Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {MultiSignerERC7913Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/signers/MultiSignerERC7913Upgradeable.sol";
import {MultiSignerERC7913WeightedUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/signers/MultiSignerERC7913WeightedUpgradeable.sol";
import {BLS2} from "../lib/BLS2.sol";

/**
 *
 * @custom:oz-upgrades-unsafe-allow constructor
 */
contract UccbAggregator is
    Initializable,
    UUPSUpgradeable,
    AccessControlUpgradeable,
    EIP712Upgradeable,
    ReentrancyGuardTransient,
    MultiSignerERC7913WeightedUpgradeable,
    IAggregator
{
    using ERC4337Utils for PackedUserOperation;

    bytes32 public constant SENDER_CONTRACT = keccak256("SENDER_CONTRACT");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    /**
     * @dev Revert if the caller is not the entry point.
     */
    modifier onlyEntryPoint() {
        address sender = msg.sender;
        require(sender == address(entryPoint()), "AccountUnauthorized");
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

    /**
     * @notice One-time initializer called by the factory through the proxy.
     */
    function initialize(address admin_) external initializer {
        assert(admin_ != address(0));

        __EIP712_init("UccbAggregator", "1");
        __AccessControl_init();
        __ERC165_init();

        _grantRole(DEFAULT_ADMIN_ROLE, admin_);
    }

    bytes private constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    /**
     * @notice Verifies a BLS12-381 signature.
     * @param payload The raw byte array message that was signed.
     * @param pubkeyG1 The public key, encoded as a 128-byte G1 point.
     * @param signatureG2 The signature, encoded as a 256-byte G2 point.
     * @return bool True if the signature is valid, false otherwise.
     */
    function verifySignature(
        bytes memory payload,
        bytes memory pubkeyG1,
        bytes memory signatureG2
    ) private view returns (bool) {
        require(pubkeyG1.length == 96, "Invalid G1 pubkey length");
        require(signatureG2.length == 192, "Invalid G2 signature length");

        BLS2.PointG1 memory pubkey = BLS2.g1Unmarshal(pubkeyG1); // 96 bytes
        BLS2.PointG2 memory signature = BLS2.g2Unmarshal(signatureG2); // 192 bytes
        BLS2.PointG2 memory message = BLS2.hashToPointG2(DST, payload);
        (bool ok, bool called) = BLS2.verifySingle(signature, pubkey, message);
        // return BLS12381Verifier.verify(pubkeyG1, signatureG2, payload);
        return called && ok;
    }

    function _decodeSignature(
        bytes calldata packedSig
    )
        private
        pure
        returns (
            bytes memory addr,
            bytes memory msig,
            bytes memory cosig,
            bytes memory sig
        )
    {
        // Sanity check to prevent out-of-bounds errors
        require(packedSig.length == 512, "Invalid signature length");

        // Slice out each segment and cast manually
        addr = bytes(packedSig[0:96]);
        cosig = bytes(packedSig[96:128]);
        msig = bytes(packedSig[128:320]);
        sig = bytes(packedSig[320:512]);
    }

    /**
     * Validate the signature of a single userOp.
     * This method should be called by bundler after EntryPointSimulation.simulateValidation() returns
     * the aggregator this account uses.
     * First it validates the signature over the userOp. Then it returns data to be used when creating the handleOps.
     * @param userOp        - The userOperation received from the user.
     * @return sigForUserOp - The value to put into the signature field of the userOp when calling handleOps.
     *                        (usually empty, unless account and aggregator support some kind of "multisig".
     */
    function validateUserOpSignature(
        PackedUserOperation calldata userOp
    ) external view override returns (bytes memory sigForUserOp) {
        require(hasRole(SENDER_CONTRACT, userOp.sender), "Invalid sender");
        // BLS12381 checks

        // Per the ERC, the "alternate signature" is often empty —
        // the account will trust the aggregator's validateSignatures()
        // call at execution time instead of checking this bytes value itself.
        return "";
    }

    /**
     * Aggregate multiple signatures into a single value.
     * This method is called off-chain to calculate the signature to pass with handleOps()
     * bundler MAY use optimized custom code to perform this aggregation.
     * @param userOps              - An array of UserOperations to collect the signatures from.
     * @return aggregatedSignature - The aggregated signature.
     */
    function aggregateSignatures(
        PackedUserOperation[] calldata userOps
    ) external view override returns (bytes memory aggregatedSignature) {
        for (uint256 i = 0; i < userOps.length; i++) {
            require(
                hasRole(SENDER_CONTRACT, userOps[i].sender),
                "Invalid sender"
            );
        }
        // BLS12381 aggregation i.e. G2_ADD

        return abi.encode(SENDER_CONTRACT); // DUMMY
    }

    /**
     * Validate an aggregated signature.
     * Reverts if the aggregated signature does not match the given list of operations.
     * @param userOps   - An array of UserOperations to validate the signature for.
     * @param signature - The aggregated signature.
     */
    function validateSignatures(
        PackedUserOperation[] calldata userOps,
        bytes calldata signature
    ) external view override onlyRole(SENDER_CONTRACT) {
        // TODO: Check that it matches
    }

    // ***** SIGNERS MANAGEMENT *****

    function addSigners(
        bytes[] memory signers
    ) public onlyRole(SENDER_CONTRACT) {
        _addSigners(signers);
    }

    function removeSigners(
        bytes[] memory signers
    ) public onlyRole(SENDER_CONTRACT) {
        _removeSigners(signers);
    }

    function setThreshold(uint64 threshold) public onlyRole(SENDER_CONTRACT) {
        _setThreshold(threshold);
    }

    function setSignerWeights(
        bytes[] memory signers,
        uint64[] memory weights
    ) public onlyRole(SENDER_CONTRACT) {
        _setSignerWeights(signers, weights);
    }

    /// STAKING

    /**
     * @notice Add stake to the EntryPoint for this paymaster.
     *
     * @param  unstakeDelaySec  Delay (seconds) before stake can be withdrawn.
     *                          Must meet the EntryPoint's minimum.
     */
    function addStake(
        uint32 unstakeDelaySec
    ) external payable onlyRole(DEFAULT_ADMIN_ROLE) {
        entryPoint().addStake{value: msg.value}(unstakeDelaySec);
    }

    /**
     * @notice Initiate the stake unlock process.  After the unstake delay
     *         has elapsed, call {withdrawStake}.
     */
    function unlockStake() external onlyRole(DEFAULT_ADMIN_ROLE) {
        entryPoint().unlockStake();
    }

    /**
     * @notice Withdraw previously unlocked stake.
     * @param  to  Recipient of the returned ETH.
     */
    function withdrawStake(
        address payable to
    ) external onlyRole(WITHDRAWER_ROLE) nonReentrant {
        assert(to != address(0));
        entryPoint().withdrawStake(to);
    }

    /// BOILERPLATE

    function _authorizeUpgrade(
        address /*newImplementation*/
    ) internal view override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(AccessControlUpgradeable) returns (bool) {
        return
            interfaceId == type(IAggregator).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
