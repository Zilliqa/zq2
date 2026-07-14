// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {Checkpoints} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";
import {AbstractSigner} from "@openzeppelin/contracts/utils/cryptography/signers/AbstractSigner.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {BLS12381} from "./BLS12381.sol";

/**
 * @dev Upgradeable variant of `MultiSignerERC7913WeightedCheckpointed`.
 *
 * Combines a checkpointed (block-height indexed) history of signer sets with an API modeled
 * after OpenZeppelin's `MultiSignerERC7913Weighted`. Instead of mutating a single "current"
 * signer set in place, this contract schedules complete signer-set snapshots ("generations")
 * to take effect at a given future block number, so signatures - and any other access-control
 * decision - can be checked against whatever signer set was, is, or will be active at any given
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
 * Failing to call `__MultiSignerERC7913WeightedCheckpointed_init` (directly, or transitively
 * through your contract's own `_init`) during initialization will leave the contract with no
 * active generation, so signature validation will always fail until a generation is scheduled.
 */
abstract contract MultiSignerERC7913WeightedCheckpointedUpgradeable is
    BLS12381,
    Initializable,
    AbstractSigner
{
    using Checkpoints for Checkpoints.Trace208;

    struct Generation {
        bytes[] signers;
        uint128 threshold;
        uint128 totalWeight;
        mapping(bytes32 signerHash => uint128 weight) weights; // 0 => not a signer
    }

    /// @custom:storage-location erc7201:zq2.storage.MultiSignerERC7913WeightedCheckpointed
    struct MultiSignerERC7913WeightedCheckpointedStorage {
        // generationId => generation data. Generation 0 is reserved for "no generation scheduled".
        mapping(uint256 generationId => Generation) generations;
        uint256 generationCount;
        // block number => generation id that becomes active at that block (and remains active
        // until superseded by a later checkpoint).
        Checkpoints.Trace208 schedule;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.storage.MultiSignerERC7913WeightedCheckpointed")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant MULTI_SIGNER_CHECKPOINT_STORAGE_SLOT =
        0xf9b51b7eea1d1d089cb8b3c9aa80c8467980d8d2b2fb095da23bb10a3a922700;

    function _getMultiSignerERC7913WeightedCheckpointedStorage()
        private
        pure
        returns (MultiSignerERC7913WeightedCheckpointedStorage storage $)
    {
        assembly {
            $.slot := MULTI_SIGNER_CHECKPOINT_STORAGE_SLOT
        }
    }

    /// @dev Emitted when a new signer set generation is scheduled.
    event SignerSetScheduled(
        uint256 indexed generationId,
        uint48 indexed effectiveBlock,
        uint128 threshold
    );

    /// @dev Emitted for each signer when a generation that authorizes them is scheduled.
    event ERC7913SignerWeightChanged(
        bytes indexed signer,
        uint128 weight,
        uint256 indexed generationId
    );

    error MultiSignerERC7913WeightedCheckpointedInvalidSigner(bytes signer);
    error MultiSignerERC7913WeightedCheckpointedDuplicateSigner(bytes signer);
    error MultiSignerERC7913WeightedCheckpointedInvalidWeight(
        bytes signer,
        uint128 weight
    );
    error MultiSignerERC7913WeightedCheckpointedMismatchedLength();
    error MultiSignerERC7913WeightedCheckpointedZeroThreshold();
    error MultiSignerERC7913WeightedCheckpointedUnreachableThreshold(
        uint128 totalWeight,
        uint128 threshold
    );
    error MultiSignerERC7913WeightedCheckpointedInvalidEffectiveBlock(
        uint48 effectiveBlock,
        uint48 lastScheduledBlock
    );

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
        bytes[] memory signers, // G1 compressed keys
        uint128[] memory weights,
        uint128 threshold_,
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

        uint128 totalWeight_ = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            bytes memory signer = signers[i];
            if (signer.length != 96) {
                revert MultiSignerERC7913WeightedCheckpointedInvalidSigner(
                    signer
                );
            }

            uint128 weight = weights[i];
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
    /// Views - current (as of block.number)
    /// ------------------------------------------------------------------

    function getSigners(
        uint64 start,
        uint64 end
    ) public view virtual returns (bytes[] memory) {
        return getSigners(start, end, type(uint48).max);
    }

    function getSignerCount() public view virtual returns (uint256) {
        return getSignerCount(type(uint48).max);
    }

    function isSigner(bytes memory signer) public view virtual returns (bool) {
        return isSigner(signer, type(uint48).max);
    }

    function signerWeight(
        bytes memory signer
    ) public view virtual returns (uint128) {
        return signerWeight(signer, type(uint48).max);
    }

    function threshold() public view virtual returns (uint128) {
        return threshold(type(uint48).max);
    }

    function totalWeight() public view virtual returns (uint128) {
        return totalWeight(type(uint48).max);
    }

    /// ------------------------------------------------------------------
    /// Views - historical / scheduled (as of an arbitrary block number)
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
    ) public view virtual returns (uint128) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage()
                .generations[_generationAt(blockNumber)]
                .weights[keccak256(signer)];
    }

    /// @dev Returns the threshold that was/is/will be active as of `blockNumber`.
    function threshold(
        uint256 blockNumber
    ) public view virtual returns (uint128) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage()
                .generations[_generationAt(blockNumber)]
                .threshold;
    }

    /// @dev Returns the total signer weight that was/is/will be active as of `blockNumber`.
    function totalWeight(
        uint256 blockNumber
    ) public view virtual returns (uint128) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage()
                .generations[_generationAt(blockNumber)]
                .totalWeight;
    }

    function _generationAt(
        uint256 blockNumber
    ) internal view virtual returns (uint256) {
        return
            _getMultiSignerERC7913WeightedCheckpointedStorage()
                .schedule
                .upperLookupRecent(uint48(blockNumber));
    }

    /// ------------------------------------------------------------------
    /// Signature validation
    /// ------------------------------------------------------------------

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
        require(packedSig.length == 520, "Invalid signature length");

        // Slice out each segment and cast manually
        key = bytes(packedSig[0:96]);
        height = uint64(bytes8(packedSig[96:104]));
        cosig = bytes32(packedSig[104:136]);
        aggsig = bytes(packedSig[136:328]);
        sig = bytes(packedSig[328:520]);
    }

    /// @dev Interprets `bitVector` as a set membership mask over the signer
    ///      range [0, 256) and returns only the selected signers' pubkeys.
    uint256 private constant MSB_MASK = (1 << 255);
    function _getCosignersFromBitVector(
        bytes32 bitVector,
        uint64 height
    ) internal view returns (bytes[] memory selected) {
        uint256 bits = uint256(bitVector);
        require(bits != 0, "no co-signers");
        uint256 n = getSignerCount(uint48(height));
        bytes[] memory allSigners = getSigners(0, uint64(n), uint48(height));

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
    ) internal view override returns (bool) {
        // Decode the signature
        (
            bytes memory pubkey,
            uint64 height,
            bytes32 cosig,
            bytes memory aggsig,
            bytes memory sig
        ) = _decodeSignature(signature);

        bytes[] memory signers = _getCosignersFromBitVector(cosig, height);

        return
            // 1. Relayer signature check
            isSigner(pubkey, height) &&
            _validateSignature(pubkey, signature[0:328], sig) &&
            // 2. Co-signers multi-signature check
            _validateSignatures(hash, signers, aggsig) &&
            _validateThreshold(signers, height);
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
        uint128 totalValidatingWeight = 0;
        for (uint256 i = 0; i < signers.length; i++) {
            totalValidatingWeight += gen.weights[keccak256(signers[i])];
        }
        return totalValidatingWeight >= gen.threshold;
    }
}
