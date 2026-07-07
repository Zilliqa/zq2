// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Checkpoints} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import {AbstractSigner} from "@openzeppelin/contracts/utils/cryptography/signers/AbstractSigner.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {BLS2} from "./BLS2.sol";

/**
 * @dev Upgradeable variant of `MultiSignerERC7913WeightedCheckpointed`.
 *
 * Combines a checkpointed (block-height indexed) history of signer sets with an API modeled
 * after OpenZeppelin's `MultiSignerERC7913Weighted`. Instead of mutating a single "current"
 * signer set in place, this contract schedules complete signer-set snapshots ("generations")
 * to take effect at a given future block number, so signatures — and any other access-control
 * decision — can be checked against whatever signer set was, is, or will be active at any given
 * block height.
 *
 * This variant follows the OpenZeppelin Upgradeable conventions:
 *
 * - No constructor logic; state is set up via `__MultiSignerERC7913WeightedCheckpointed_init`,
 *   guarded by {Initializable-onlyInitializing}, to be called from your contract's initializer.
 * - All state lives in a single struct at an ERC-7201 namespaced storage slot, so this
 *   contract is safe to use behind a proxy and safe to combine with other upgradeable base
 *   contracts without storage collisions, and without needing manual `__gap` reservations.
 *
 * IMPORTANT: The storage namespace string below (`"openzeppelin.storage.
 * MultiSignerERC7913WeightedCheckpointed"`) is used here only because this contract mirrors
 * an OpenZeppelin API; it is NOT an official OpenZeppelin contract. If you fork or rename this
 * contract, change the namespace string (and recompute `_STORAGE_LOCATION`) to something
 * project-specific to avoid any risk of colliding with a real OpenZeppelin contract that might
 * use the same namespace in the future.
 *
 * Example of usage:
 *
 * ```solidity
 * contract MyWeightedCheckpointedAccount is
 *     Initializable,
 *     AccountUpgradeable,
 *     MultiSignerERC7913WeightedCheckpointedUpgradeable
 * {
 *     function initialize(
 *         bytes[] memory signers,
 *         uint64[] memory weights,
 *         uint64 threshold,
 *         uint48 effectiveBlock
 *     ) public initializer {
 *         __MultiSignerERC7913WeightedCheckpointed_init(signers, weights, threshold, effectiveBlock);
 *     }
 *
 *     function scheduleSignerSet(
 *         bytes[] memory signers,
 *         uint64[] memory weights,
 *         uint64 threshold,
 *         uint48 effectiveBlock
 *     ) public onlyEntryPointOrSelf {
 *         _scheduleSignerSet(signers, weights, threshold, effectiveBlock);
 *     }
 * }
 * ```
 *
 * Failing to call `__MultiSignerERC7913WeightedCheckpointed_init` (directly, or transitively
 * through your contract's own `_init`) during initialization will leave the contract with no
 * active generation, so signature validation will always fail until a generation is scheduled.
 */
abstract contract MultiSignerERC7913WeightedCheckpointedUpgradeable is
    Initializable,
    AbstractSigner
{
    using Checkpoints for Checkpoints.Trace208;

    struct Generation {
        bytes[] signers;
        uint64 threshold;
        uint64 totalWeight;
        mapping(bytes32 signerHash => uint64 weight) weights; // 0 => not a signer
    }

    /// @custom:storage-location erc7201:openzeppelin.storage.MultiSignerERC7913WeightedCheckpointed
    struct MultiSignerERC7913WeightedCheckpointedStorage {
        // generationId => generation data. Generation 0 is reserved for "no generation scheduled".
        mapping(uint256 generationId => Generation) generations;
        uint256 generationCount;
        // block number => generation id that becomes active at that block (and remains active
        // until superseded by a later checkpoint).
        Checkpoints.Trace208 schedule;
    }

    // keccak256(abi.encode(uint256(keccak256("zq2.storage.MultiSignerERC7913WeightedCheckpointed")) - 1)) & ~bytes32(uint256(0xff))
    bytes32
        private
        constant MultiSignerERC7913WeightedCheckpointedStorageLocation =
            0x55a01cc5201b55d0eb0c67e940fdae9e2a47e4c946d455a9f6df2194d229ec00;

    function _getMultiSignerERC7913WeightedCheckpointedStorage()
        private
        pure
        returns (MultiSignerERC7913WeightedCheckpointedStorage storage $)
    {
        assembly {
            $.slot := MultiSignerERC7913WeightedCheckpointedStorageLocation
        }
    }

    /// @dev Emitted when a new signer set generation is scheduled.
    event SignerSetScheduled(
        uint256 indexed generationId,
        uint48 indexed effectiveBlock,
        uint64 threshold
    );

    /// @dev Emitted for each signer when a generation that authorizes them is scheduled.
    event ERC7913SignerWeightChanged(
        bytes indexed signer,
        uint64 weight,
        uint256 indexed generationId
    );

    error MultiSignerERC7913WeightedCheckpointedInvalidSigner(bytes signer);
    error MultiSignerERC7913WeightedCheckpointedDuplicateSigner(bytes signer);
    error MultiSignerERC7913WeightedCheckpointedInvalidWeight(
        bytes signer,
        uint64 weight
    );
    error MultiSignerERC7913WeightedCheckpointedMismatchedLength();
    error MultiSignerERC7913WeightedCheckpointedZeroThreshold();
    error MultiSignerERC7913WeightedCheckpointedUnreachableThreshold(
        uint64 totalWeight,
        uint64 threshold
    );
    error MultiSignerERC7913WeightedCheckpointedInvalidEffectiveBlock(
        uint48 effectiveBlock,
        uint48 lastScheduledBlock
    );

    /// ------------------------------------------------------------------
    /// Initialization
    /// ------------------------------------------------------------------

    /**
     * @dev Initializes the contract by scheduling an initial signer set. See
     * {_scheduleSignerSet} for the full requirements on the arguments.
     *
     * Typically called once, from your contract's own initializer function.
     */
    function __MultiSignerERC7913WeightedCheckpointed_init(
        bytes[] memory signers,
        uint64[] memory weights,
        uint64 threshold_,
        uint48 effectiveBlock
    ) internal onlyInitializing {
        __MultiSignerERC7913WeightedCheckpointed_init_unchained(
            signers,
            weights,
            threshold_,
            effectiveBlock
        );
    }

    function __MultiSignerERC7913WeightedCheckpointed_init_unchained(
        bytes[] memory signers,
        uint64[] memory weights,
        uint64 threshold_,
        uint48 effectiveBlock
    ) internal onlyInitializing {
        _scheduleSignerSet(signers, weights, threshold_, effectiveBlock);
    }

    /// ------------------------------------------------------------------
    /// Scheduling
    /// ------------------------------------------------------------------

    /**
     * @dev Schedules a new signer set, with corresponding weights and threshold, to become
     * active at `effectiveBlock`. Internal version without access control.
     *
     * This is a full replacement: it does not merge with the previously active generation.
     * Every signer that should remain authorized after `effectiveBlock` must be included again.
     *
     * Requirements:
     *
     * - `signers` and `weights` must have the same, non-zero length. Reverts with
     *   {MultiSignerERC7913WeightedCheckpointedMismatchedLength} on mismatch.
     * - Each signer must be at least 20 bytes long. Reverts with
     *   {MultiSignerERC7913WeightedCheckpointedInvalidSigner} if not.
     * - Each signer must not repeat within `signers`. Reverts with
     *   {MultiSignerERC7913WeightedCheckpointedDuplicateSigner} if so.
     * - Each weight must be greater than 0. Reverts with
     *   {MultiSignerERC7913WeightedCheckpointedInvalidWeight} if not.
     * - `threshold_` must be greater than 0. Reverts with
     *   {MultiSignerERC7913WeightedCheckpointedZeroThreshold} if not.
     * - `threshold_` must be reachable given the sum of `weights`. Reverts with
     *   {MultiSignerERC7913WeightedCheckpointedUnreachableThreshold} if not.
     * - `effectiveBlock` must be greater than or equal to the block number of the last
     *   scheduled generation (schedules must be created in non-decreasing block order).
     *   Reverts with {MultiSignerERC7913WeightedCheckpointedInvalidEffectiveBlock} if not.
     *   Scheduling twice for the *same* block overwrites the pending schedule for that block
     *   (the earlier of the two calls in the same block is superseded, not merged).
     *
     * This function does not validate that signers are controlled or represent appropriate
     * entities, matching `MultiSignerERC7913._addSigners`. Integrators must ensure signers are
     * properly validated before scheduling them.
     *
     * Emits a {SignerSetScheduled} event and a {ERC7913SignerWeightChanged} event for each signer.
     *
     * This function can be called both during initialization (guarded transitively by
     * `onlyInitializing` via `__MultiSignerERC7913WeightedCheckpointed_init`) and afterwards
     * (guarded by whatever access control your concrete contract wraps around it), so it is
     * intentionally not restricted to `onlyInitializing` itself.
     */
    function _scheduleSignerSet(
        bytes[] memory signers,
        uint64[] memory weights,
        uint64 threshold_,
        uint48 effectiveBlock
    ) internal virtual returns (uint256 generationId) {
        MultiSignerERC7913WeightedCheckpointedStorage
            storage $ = _getMultiSignerERC7913WeightedCheckpointedStorage();

        if (signers.length != weights.length || signers.length == 0) {
            revert MultiSignerERC7913WeightedCheckpointedMismatchedLength();
        }

        (bool exists, uint48 lastKey, ) = $.schedule.latestCheckpoint();
        if (exists && effectiveBlock < lastKey) {
            revert MultiSignerERC7913WeightedCheckpointedInvalidEffectiveBlock(
                effectiveBlock,
                lastKey
            );
        }

        generationId = ++$.generationCount;
        Generation storage gen = $.generations[generationId];

        uint64 totalWeight_ = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            bytes memory signer = signers[i];
            if (signer.length < 20) {
                revert MultiSignerERC7913WeightedCheckpointedInvalidSigner(
                    signer
                );
            }

            uint64 weight = weights[i];
            if (weight == 0) {
                revert MultiSignerERC7913WeightedCheckpointedInvalidWeight(
                    signer,
                    weight
                );
            }

            bytes32 signerHash = keccak256(signer);
            if (gen.weights[signerHash] != 0) {
                revert MultiSignerERC7913WeightedCheckpointedDuplicateSigner(
                    signer
                );
            }

            gen.weights[signerHash] = weight;
            totalWeight_ += weight;

            emit ERC7913SignerWeightChanged(signer, weight, generationId);
        }

        if (threshold_ == 0) {
            revert MultiSignerERC7913WeightedCheckpointedZeroThreshold();
        }
        if (totalWeight_ < threshold_) {
            revert MultiSignerERC7913WeightedCheckpointedUnreachableThreshold(
                totalWeight_,
                threshold_
            );
        }

        gen.signers = signers;
        gen.threshold = threshold_;
        gen.totalWeight = totalWeight_;

        // Overwrites the checkpoint if `effectiveBlock == lastKey`, otherwise pushes a new one.
        $.schedule.push(effectiveBlock, uint208(generationId));

        emit SignerSetScheduled(generationId, effectiveBlock, threshold_);
    }

    /// ------------------------------------------------------------------
    /// Views — current (as of block.number)
    /// ------------------------------------------------------------------

    function getSigners(
        uint64 start,
        uint64 end
    ) public view virtual returns (bytes[] memory) {
        return getSigners(start, end, block.number);
    }

    function getSignerCount() public view virtual returns (uint256) {
        return getSignerCount(block.number);
    }

    function isSigner(bytes memory signer) public view virtual returns (bool) {
        return isSigner(signer, block.number);
    }

    function signerWeight(
        bytes memory signer
    ) public view virtual returns (uint64) {
        return signerWeight(signer, block.number);
    }

    function threshold() public view virtual returns (uint64) {
        return threshold(block.number);
    }

    function totalWeight() public view virtual returns (uint64) {
        return totalWeight(block.number);
    }

    /// ------------------------------------------------------------------
    /// Views — historical / scheduled (as of an arbitrary block number)
    /// ------------------------------------------------------------------

    /**
     * @dev Returns a slice of the set of authorized signers as of `blockNumber`.
     *
     * Using `start = 0` and `end = type(uint64).max` returns the entire set. See the caveats
     * in `MultiSignerERC7913.getSigners` about the cost of large slices — the same applies here.
     */
    function getSigners(
        uint64 start,
        uint64 end,
        uint256 blockNumber
    ) public view virtual returns (bytes[] memory) {
        bytes[]
            storage signers = _getMultiSignerERC7913WeightedCheckpointedStorage()
                .generations[_generationAt(blockNumber)]
                .signers;
        uint256 len = signers.length;
        uint256 stop = end > len ? len : end;
        if (start >= stop) return new bytes[](0);

        bytes[] memory result = new bytes[](stop - start);
        for (uint256 i = start; i < stop; i++) {
            result[i - start] = signers[i];
        }
        return result;
    }

    /// @dev Returns the number of authorized signers as of `blockNumber`.
    function getSignerCount(
        uint256 blockNumber
    ) public view virtual returns (uint256) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage()
                .generations[_generationAt(blockNumber)]
                .signers
                .length;
    }

    /// @dev Returns whether `signer` was/is/will be authorized as of `blockNumber`.
    function isSigner(
        bytes memory signer,
        uint256 blockNumber
    ) public view virtual returns (bool) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage()
                .generations[_generationAt(blockNumber)]
                .weights[keccak256(signer)] != 0;
    }

    /// @dev Returns the weight of `signer` as of `blockNumber`. Returns 0 if not authorized.
    function signerWeight(
        bytes memory signer,
        uint256 blockNumber
    ) public view virtual returns (uint64) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage()
                .generations[_generationAt(blockNumber)]
                .weights[keccak256(signer)];
    }

    /// @dev Returns the threshold that was/is/will be active as of `blockNumber`.
    function threshold(
        uint256 blockNumber
    ) public view virtual returns (uint64) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage()
                .generations[_generationAt(blockNumber)]
                .threshold;
    }

    /// @dev Returns the total signer weight that was/is/will be active as of `blockNumber`.
    function totalWeight(
        uint256 blockNumber
    ) public view virtual returns (uint64) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage()
                .generations[_generationAt(blockNumber)]
                .totalWeight;
    }

    /// @dev Returns the id of the generation that was/is/will be active at `blockNumber`.
    /// Returns 0 if no generation had been scheduled yet as of that block.
    function generationAt(
        uint256 blockNumber
    ) public view virtual returns (uint256) {
        return _generationAt(blockNumber);
    }

    /// @dev Returns the total number of generations scheduled so far (regardless of whether
    /// their effective block has passed).
    function generationCount() public view virtual returns (uint256) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage().generationCount;
    }

    function _generationAt(
        uint256 blockNumber
    ) internal view virtual returns (uint256) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage()
                .schedule
                .upperLookup(uint48(blockNumber));
    }

    /// ------------------------------------------------------------------
    /// Signature validation
    /// ------------------------------------------------------------------

    bytes private constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    /**
     * @notice Verifies a BLS12-381 signature.
     * @param payload The raw byte array message that was signed.
     * @param pubkeyG1 The public key, encoded as a 128-byte G1 point.
     * @param signatureG2 The signature, encoded as a 256-byte G2 point.
     * @return bool True if the signature is valid, false otherwise.
     */
    function _verifySignature(
        bytes memory payload,
        bytes memory pubkeyG1,
        bytes memory signatureG2
    ) private view returns (bool) {
        BLS2.PointG1 memory pubkey = BLS2.g1UnmarshalCompressed(pubkeyG1);
        BLS2.PointG2 memory signature = BLS2.g2Unmarshal(signatureG2);
        BLS2.PointG2 memory message = BLS2.hashToPointG2(DST, payload);
        (bool ok, bool called) = BLS2.verifySingle(signature, pubkey, message);
        return called && ok;
    }

    function _decodeSignature(
        bytes calldata packedSig
    )
        private
        pure
        returns (
            bytes memory key,
            uint64 height,
            bytes32 cosig,
            bytes memory aggsig,
            bytes memory sig
        )
    {
        // Sanity check to prevent out-of-bounds errors
        require(packedSig.length == 472, "Invalid signature length");

        // Slice out each segment and cast manually
        key = bytes(packedSig[0:48]);
        height = uint64(bytes8(packedSig[48:56]));
        cosig = bytes32(packedSig[56:88]);
        aggsig = bytes(packedSig[88:280]);
        sig = bytes(packedSig[280:472]);
    }

    uint256 constant MSB_MASK = (1 << 255);
    /// @dev Interprets `bitVector` as a set membership mask over the signer
    ///      range [0, 256) and returns only the selected signers' pubkeys.
    function _getCosignersFromBitVector(
        bytes32 bitVector,
        uint64 height
    ) internal view returns (bytes[] memory selected) {
        uint256 n = getSignerCount(uint48(height));
        bytes[] memory allSigners = getSigners(0, uint64(n), uint48(height));
        uint256 bits = uint256(bitVector);

        selected = new bytes[](n); // over-allocate, trim below
        uint256 count;

        for (uint256 i = 0; i < n; i++) {
            if (bits == 0) break; // quick exit
            if (bits & MSB_MASK != 0) {
                selected[count] = allSigners[i];
                unchecked {
                    ++count;
                }
            }
            bits <<= 1;
        }

        // shrink the array's length in place - safe since we're only
        // reducing it, never exceeding the original allocation
        assembly {
            mstore(selected, count)
        }
    }

    /**
     * @dev Decodes, validates the signature and checks the signers are authorized as of the
     * current block (`block.number`). Mirrors `MultiSignerERC7913._rawSignatureValidation`.
     */
    function _rawSignatureValidation(
        bytes32 hash,
        bytes calldata signature
    ) internal view virtual override returns (bool) {
        // 0. Decode the signature
        (
            bytes memory pubkey,
            uint64 height,
            bytes32 cosig,
            bytes memory aggsig,
            bytes memory sig
        ) = _decodeSignature(signature);

        // 1. Relayer signature check
        if (
            !isSigner(pubkey, uint48(height)) ||
            !_verifySignature(signature[0:280], pubkey, sig)
        ) return false;

        // 2. Co-signers multi-signature check
        bytes[] memory signers = _getCosignersFromBitVector(cosig, height);

        return
            _validateSignatures(hash, signers, aggsig) &&
            _validateThreshold(signers, height);
    }

    /// @dev See `MultiSignerERC7913._validateSignatures`. Sorting signers by their `keccak256`
    /// hash improves gas efficiency, as with the non-checkpointed version.
    function _validateSignatures(
        bytes32 hash,
        bytes[] memory signers,
        bytes memory aggregate
    ) internal view virtual returns (bool valid) {
        BLS2.PointG1 memory pubkey = BLS2.aggregatePublicKeys(signers);
        BLS2.PointG2 memory signature = BLS2.g2Unmarshal(aggregate);
        BLS2.PointG2 memory message = BLS2.hashToPointG2(
            DST,
            bytes.concat(hash)
        );
        (bool ok, bool called) = BLS2.verifySingle(signature, pubkey, message);
        return called && ok;
    }

    /// @dev Validates that the total weight of `signers`, evaluated against the generation
    /// active at the current block, meets that generation's threshold. Assumes `signers` were
    /// already validated by {_validateSignatures}. Returns `false` if no generation has been
    /// scheduled yet as of `block.number`.
    function _validateThreshold(
        bytes[] memory signers,
        uint64 height
    ) internal view virtual returns (bool) {
        MultiSignerERC7913WeightedCheckpointedStorage
            storage $ = _getMultiSignerERC7913WeightedCheckpointedStorage();
        uint256 generationId = _generationAt(uint48(height));
        if (generationId == 0) return false;

        Generation storage gen = $.generations[generationId];
        uint64 totalValidatingWeight = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            totalValidatingWeight += gen.weights[keccak256(signers[i])];
        }
        return totalValidatingWeight >= gen.threshold;
    }
}
