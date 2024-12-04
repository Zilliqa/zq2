// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Deque, Withdrawal} from "./utils/deque.sol";

using Deque for Deque.Withdrawals;


/// Argument has unexpected length
/// @param argument name of argument
/// @param required expected length
error UnexpectedArgumentLength(string argument, uint256 required);

/// Maximum number of stakers has been reached
error TooManyStakers();
/// Key already staked 
error KeyAlreadyStaked();
/// Key is not staked
error KeyNotStaked();
/// Stake amount less than minimum
error StakeAmountTooLow();

struct CommitteeStakerEntry {
    // The index of the value in the `stakers` array plus 1.
    // Index 0 is used to mean a value is not present.
    uint256 index;
    // Invariant: `balance >= minimumStake`
    uint256 balance;
}

struct Committee {
    // Invariant: Equal to the sum of `balances` in `stakers`.
    uint256 totalStake;
    bytes[] stakerKeys;
    mapping(bytes => CommitteeStakerEntry) stakers;
}

struct Staker {
    // The address used for authenticating requests from this staker to the deposit contract.
    // Invariant: `controlAddress != address(0)`.
    address controlAddress;
    // The address which rewards for this staker will be sent to.
    address rewardAddress;
    // libp2p peer ID, corresponding to the staker's `blsPubKey`
    bytes peerId;
    // Invariants: Items are always sorted by `startedAt`. No two items have the same value of `startedAt`.
    Deque.Withdrawals withdrawals;
}

// Parameters passed to the deposit contract constructor, for each staker who should be in the initial committee.
struct InitialStaker {
    bytes blsPubKey;
    bytes peerId;
    address rewardAddress;
    address controlAddress;
    uint256 amount;
}

contract DepositInit is UUPSUpgradeable {
    // Emitted to inform that a new staker identified by `blsPubKey`
    // is going to be added to the committee `atFutureBlock`, increasing
    // the total stake by `newStake`
    event StakerAdded(bytes blsPubKey, uint256 atFutureBlock, uint256 newStake);

    // Emitted to inform that the staker identified by `blsPubKey`
    // is going to be removed from the committee `atFutureBlock`
    event StakerRemoved(bytes blsPubKey, uint256 atFutureBlock);

    // Emitted to inform that the deposited stake of the staker
    // identified by `blsPubKey` is going to change to `newStake`
    // at `atFutureBlock`
    event StakeChanged(
        bytes blsPubKey,
        uint256 atFutureBlock,
        uint256 newStake
    );

    // Emitted to inform that the staker identified by `blsPubKey`
    // has updated its data that can be refetched using `getStakerData()`
    event StakerUpdated(bytes blsPubKey);

    uint64 public constant VERSION = 1;

    /// @custom:storage-location erc7201:zilliqa.storage.DepositStorage
    struct DepositStorage {
        // The committee in the current epoch and the 2 epochs following it. The value for the current epoch
        // is stored at index (currentEpoch() % 3).
        Committee[3] _committee;
        // All stakers. Keys into this map are stored by the `Committee`.
        mapping(bytes => Staker) _stakersMap;
        // Mapping from `controlAddress` to `blsPubKey` for each staker.
        mapping(address => bytes) _stakerKeys;
        // The latest epoch for which the committee was calculated. It is implied that no changes have (yet) occurred in
        // future epochs, either because those epochs haven't happened yet or because they have happened, but no deposits
        // or withdrawals were made.
        uint64 latestComputedEpoch;
        uint256 minimumStake;
        uint256 maximumStakers;
        uint64 blocksPerEpoch;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.storage.DepositStorage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant DEPOSIT_STORAGE_LOCATION =
        0x958a6cf6390bd7165e3519675caa670ab90f0161508a9ee714d3db7edc507400;

    function _getDepositStorage()
        private
        pure
        returns (DepositStorage storage $)
    {
        assembly {
            $.slot := DEPOSIT_STORAGE_LOCATION
        }
    }

    function version() public view returns (uint64) {
        return _getInitializedVersion();
    }

    function _authorizeUpgrade(
        // solhint-disable-next-line no-unused-vars
        address newImplementation
    ) internal virtual override {
        require(
            msg.sender == address(0),
            "system contract must be upgraded by the system"
        );
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        uint256 _minimumStake,
        uint256 _maximumStakers,
        uint64 _blocksPerEpoch,
        InitialStaker[] memory initialStakers
    ) public initializer {
        __UUPSUpgradeable_init_unchained();
        DepositStorage storage $ = _getDepositStorage();

        $.minimumStake = _minimumStake;
        $.maximumStakers = _maximumStakers;
        $.blocksPerEpoch = _blocksPerEpoch;
        $.latestComputedEpoch = currentEpoch();

        for (uint256 i = 0; i < initialStakers.length; i++) {
            InitialStaker memory initialStaker = initialStakers[i];
            bytes memory blsPubKey = initialStaker.blsPubKey;
            bytes memory peerId = initialStaker.peerId;
            address rewardAddress = initialStaker.rewardAddress;
            address controlAddress = initialStaker.controlAddress;
            uint256 amount = initialStaker.amount;

            if (blsPubKey.length != 48) {
                revert UnexpectedArgumentLength("bls public key", 48);
            }
            if (peerId.length != 38) {
                revert UnexpectedArgumentLength("peer id", 38);
            }
            require(
                controlAddress != address(0),
                "control address cannot be zero"
            );

            Committee storage currentCommittee = committee();
            if (currentCommittee.stakerKeys.length >= $.maximumStakers) {
                revert TooManyStakers();
            }
            Staker storage staker = $._stakersMap[blsPubKey];
            // This must be a new staker, meaning the control address must be zero.
            if (staker.controlAddress != address(0)) {
                revert KeyAlreadyStaked();
            }
            if (amount < $.minimumStake) {
                revert StakeAmountTooLow();
            }

            $._stakerKeys[controlAddress] = blsPubKey;
            staker.peerId = peerId;
            staker.rewardAddress = rewardAddress;
            staker.controlAddress = controlAddress;

            currentCommittee.totalStake += amount;
            currentCommittee.stakers[blsPubKey].balance = amount;
            currentCommittee.stakers[blsPubKey].index =
                currentCommittee.stakerKeys.length +
                1;
            currentCommittee.stakerKeys.push(blsPubKey);

            emit StakerAdded(blsPubKey, block.number, amount);
        }
    }

    function currentEpoch() public view returns (uint64) {
        DepositStorage storage $ = _getDepositStorage();
        return uint64(block.number / $.blocksPerEpoch);
    }

    function committee() private view returns (Committee storage) {
        DepositStorage storage $ = _getDepositStorage();
        if ($.latestComputedEpoch <= currentEpoch()) {
            // If the current epoch is after the latest computed epoch, it is implied that no changes have happened to
            // the committee since the latest computed epoch. Therefore, it suffices to return the committee at that
            // latest computed epoch.
            return $._committee[$.latestComputedEpoch % 3];
        } else {
            // Otherwise, the committee has been changed. The caller who made the change will have pre-computed the
            // result for us, so we can just return it.
            return $._committee[currentEpoch() % 3];
        }
    }

    function minimumStake() public view returns (uint256) {
        DepositStorage storage $ = _getDepositStorage();
        return $.minimumStake;
    }
}
