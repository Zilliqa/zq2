// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";

struct Withdrawal {
    uint256 startedAt;
    uint256 amount;
}

// Implementation of a double-ended queue of `Withdrawal`s, backed by a circular buffer.
library Deque {
    struct Withdrawals {
        Withdrawal[] values;
        // The physical index of the first element, if it exists. If `len == 0`, the value of `head` is unimportant.
        uint256 head;
        // The number of elements in the queue.
        uint256 len;
    }

    // Returns the physical index of an element, given its logical index.
    function physicalIdx(
        Withdrawals storage deque,
        uint256 idx
    ) internal view returns (uint256) {
        uint256 physical = deque.head + idx;
        // Wrap the physical index in case it is out-of-bounds of the buffer.
        if (physical >= deque.values.length) {
            return physical - deque.values.length;
        } else {
            return physical;
        }
    }

    function length(Withdrawals storage deque) internal view returns (uint256) {
        return deque.len;
    }

    // Get the element at the given logical index. Reverts if `idx >= queue.length()`.
    function get(
        Withdrawals storage deque,
        uint256 idx
    ) internal view returns (Withdrawal storage) {
        if (idx >= deque.len) {
            revert("element does not exist");
        }

        uint256 pIdx = physicalIdx(deque, idx);
        return deque.values[pIdx];
    }

    // Push an empty element to the back of the queue. Returns a reference to the new element.
    function pushBack(
        Withdrawals storage deque
    ) internal returns (Withdrawal storage) {
        // Add more space in the buffer if it is full.
        if (deque.len == deque.values.length) {
            deque.values.push();
        }

        uint256 idx = physicalIdx(deque, deque.len);
        deque.len += 1;

        return deque.values[idx];
    }

    // Pop an element from the front of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function popFront(
        Withdrawals storage deque
    ) internal returns (Withdrawal storage) {
        if (deque.len == 0) {
            revert("queue is empty");
        }

        uint256 oldHead = deque.head;
        deque.head = physicalIdx(deque, 1);
        deque.len -= 1;
        return deque.values[oldHead];
    }

    // Peeks the element at the back of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function back(
        Withdrawals storage deque
    ) internal view returns (Withdrawal storage) {
        if (deque.len == 0) {
            revert("queue is empty");
        }

        return get(deque, deque.len - 1);
    }

    // Peeks the element at the front of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function front(
        Withdrawals storage deque
    ) internal view returns (Withdrawal storage) {
        if (deque.len == 0) {
            revert("queue is empty");
        }

        return get(deque, 0);
    }
}

using Deque for Deque.Withdrawals;

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

contract DepositInit is UUPSUpgradeable, Ownable2StepUpgradeable {

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
    bytes32 private constant DepositStorageLocation = 0x958a6cf6390bd7165e3519675caa670ab90f0161508a9ee714d3db7edc507400;

    function _getDepositStorage() private pure returns (DepositStorage storage $) {
        assembly {
            $.slot := DepositStorageLocation
        }
    }

    function version() public view returns(uint64) {
        return _getInitializedVersion();
    } 

    function __Deposit_init(address initialOwner) internal onlyInitializing {
        __Ownable2Step_init_unchained();
        __Ownable_init_unchained(initialOwner);
        __UUPSUpgradeable_init_unchained();
    }

    function _authorizeUpgrade(address newImplementation) internal onlyOwner virtual override {}

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address initialOwner,
        uint256 _minimumStake,
        uint256 _maximumStakers,
        uint64 _blocksPerEpoch,
        InitialStaker[] memory initialStakers
    ) initializer public {
        __Deposit_init(initialOwner);
        DepositStorage storage $ = _getDepositStorage();

        $.minimumStake = _minimumStake;
        $.maximumStakers = _maximumStakers;
        $.blocksPerEpoch = _blocksPerEpoch;
        $.latestComputedEpoch = currentEpoch();

        for (uint i = 0; i < initialStakers.length; i++) {
            InitialStaker memory initialStaker = initialStakers[i];
            bytes memory blsPubKey = initialStaker.blsPubKey;
            bytes memory peerId = initialStaker.peerId;
            address rewardAddress = initialStaker.rewardAddress;
            address controlAddress = initialStaker.controlAddress;
            uint256 amount = initialStaker.amount;

            require(blsPubKey.length == 48);
            require(peerId.length == 38);
            require(
                controlAddress != address(0),
                "control address cannot be zero"
            );

            Committee storage currentCommittee = committee();
            require(
                currentCommittee.stakerKeys.length < $.maximumStakers,
                "too many stakers"
            );

            Staker storage staker = $._stakersMap[blsPubKey];
            // This must be a new staker, meaning the control address must be zero.
            require(
                staker.controlAddress == address(0),
                "staker already exists"
            );

            if (amount < $.minimumStake) {
                revert("stake is less than minimum stake");
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
        }
    }

    // automatically incrementing the version number allows for
    // upgrading the contract without manually specifying the next
    // version number in the source file - use with caution since
    // it won't be possible to identify the actual version of the
    // source file without a hardcoded version number, but storing
    // the file versions in separate folders would help
    function reinitialize() reinitializer(version() + 1) public {
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
