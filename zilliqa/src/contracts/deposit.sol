// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

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

contract Deposit {
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

    uint256 public minimumStake;
    uint256 public maximumStakers;

    uint64 public blocksPerEpoch;

    constructor(
        uint256 _minimumStake,
        uint256 _maximumStakers,
        uint64 _blocksPerEpoch,
        InitialStaker[] memory initialStakers
    ) {
        minimumStake = _minimumStake;
        maximumStakers = _maximumStakers;
        blocksPerEpoch = _blocksPerEpoch;
        latestComputedEpoch = currentEpoch();

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

            require(
                committee().stakerKeys.length < maximumStakers,
                "too many stakers"
            );

            Staker storage staker = _stakersMap[blsPubKey];
            // This must be a new staker, meaning the control address must be zero.
            require(
                staker.controlAddress == address(0),
                "staker already exists"
            );

            if (amount < minimumStake) {
                revert("stake is less than minimum stake");
            }

            _stakerKeys[controlAddress] = blsPubKey;
            staker.peerId = peerId;
            staker.rewardAddress = rewardAddress;
            staker.controlAddress = controlAddress;

            Committee storage currentCommittee = _committee[currentEpoch() % 3];
            currentCommittee.totalStake += amount;
            currentCommittee.stakers[blsPubKey].balance = amount;
            currentCommittee.stakers[blsPubKey].index =
                currentCommittee.stakerKeys.length +
                1;
            currentCommittee.stakerKeys.push(blsPubKey);
        }
    }

    function currentEpoch() public view returns (uint64) {
        return uint64(block.number / blocksPerEpoch);
    }

    function committee() private view returns (Committee storage) {
        if (latestComputedEpoch <= currentEpoch()) {
            // If the current epoch is after the latest computed epoch, it is implied that no changes have happened to
            // the committee since the latest computed epoch. Therefore, it suffices to return the committee at that
            // latest computed epoch.
            return _committee[latestComputedEpoch % 3];
        } else {
            // Otherwise, the committee has been changed. The caller who made the change will have pre-computed the
            // result for us, so we can just return it.
            return _committee[currentEpoch() % 3];
        }
    }

    function leaderFromRandomness(
        uint256 randomness
    ) private view returns (bytes memory) {
        // Get a random number in the inclusive range of 0 to (totalStake - 1)
        uint256 position = randomness % committee().totalStake;
        uint256 cummulative_stake = 0;

        // TODO: Consider binary search for performance. Or consider an alias method for O(1) performance.
        for (uint256 i = 0; i < committee().stakerKeys.length; i++) {
            bytes memory stakerKey = committee().stakerKeys[i];
            uint256 stakedBalance = committee().stakers[stakerKey].balance;

            cummulative_stake += stakedBalance;

            if (position < cummulative_stake) {
                return stakerKey;
            }
        }

        revert("Unable to select next leader");
    }

    function leaderAtView(
        uint256 viewNumber
    ) public view returns (bytes memory) {
        uint256 randomness = uint256(
            keccak256(bytes.concat(bytes32(viewNumber)))
        );
        return leaderFromRandomness(randomness);
    }

    function getStakers() public view returns (bytes[] memory) {
        return committee().stakerKeys;
    }

    function getStakersData()
        public
        view
        returns (
            bytes[] memory stakerKeys,
            uint256[] memory balances,
            Staker[] memory stakers
        )
    {
        Committee storage currentCommittee = committee();
        stakerKeys = currentCommittee.stakerKeys;
        balances = new uint256[](stakerKeys.length);
        stakers = new Staker[](stakerKeys.length);
        for (uint i = 0; i < stakerKeys.length; i++) {
            bytes memory key = stakerKeys[i];
            balances[i] = currentCommittee.stakers[key].balance;
            stakers[i] = _stakersMap[key];
        }
    }

    function getStake(bytes calldata blsPubKey) public view returns (uint256) {
        require(blsPubKey.length == 48);

        // We don't need to check if `blsPubKey` is in `stakerKeys` here. If the `blsPubKey` is not a staker, the
        // balance will default to zero.
        return committee().stakers[blsPubKey].balance;
    }

    function getRewardAddress(
        bytes calldata blsPubKey
    ) public view returns (address) {
        require(blsPubKey.length == 48);
        if (_stakersMap[blsPubKey].controlAddress == address(0)) {
            revert("not staked");
        }
        return _stakersMap[blsPubKey].rewardAddress;
    }

    function getPeerId(
        bytes calldata blsPubKey
    ) public view returns (bytes memory) {
        require(blsPubKey.length == 48);
        if (_stakersMap[blsPubKey].controlAddress == address(0)) {
            revert("not staked");
        }
        return _stakersMap[blsPubKey].peerId;
    }

    function updateLatestComputedEpoch() internal {
        // If the latest computed epoch is less than two epochs ahead of the current one, we must fill in the missing
        // epochs. This just involves copying the committee from the previous epoch to the next one. It is assumed that
        // the caller will then want to update the future epochs.
        if (latestComputedEpoch < currentEpoch() + 2) {
            Committee storage latestComputedCommittee = _committee[
                latestComputedEpoch % 3
            ];
            // Note the early exit condition if `latestComputedEpoch + 3` which ensures this loop will not run more
            // than twice. This is acceptable because we only store 3 committees at a time, so once we have updated two
            // of them to the latest computed committee, there is no more work to do.
            for (
                uint64 i = latestComputedEpoch + 1;
                i <= currentEpoch() + 2 && i < latestComputedEpoch + 3;
                i++
            ) {
                // The operation we want to do is: `_committee[i % 3] = latestComputedCommittee` but we need to do it
                // explicitly because `stakers` is a mapping.

                // Delete old keys from `_committee[i % 3].stakers`.
                for (uint j = 0; j < _committee[i % 3].stakerKeys.length; j++) {
                    delete _committee[i % 3].stakers[
                        _committee[i % 3].stakerKeys[j]
                    ];
                }

                _committee[i % 3].totalStake = latestComputedCommittee
                    .totalStake;
                _committee[i % 3].stakerKeys = latestComputedCommittee
                    .stakerKeys;
                for (
                    uint j = 0;
                    j < latestComputedCommittee.stakerKeys.length;
                    j++
                ) {
                    bytes storage stakerKey = latestComputedCommittee
                        .stakerKeys[j];
                    _committee[i % 3].stakers[
                        stakerKey
                    ] = latestComputedCommittee.stakers[stakerKey];
                }
            }

            latestComputedEpoch = currentEpoch() + 2;
        }
    }

    // keep in-sync with zilliqa/src/precompiles.rs
    function _popVerify(
        bytes memory pubkey,
        bytes memory signature
    ) internal view returns (bool) {
        bytes memory input = abi.encodeWithSelector(
            hex"bfd24965", // bytes4(keccak256("popVerify(bytes,bytes)"))
            signature,
            pubkey
        );
        uint inputLength = input.length;
        bytes memory output = new bytes(32);
        bool success;
        assembly {
            success := staticcall(
                gas(),
                0x5a494c80, // "ZIL\x80"
                add(input, 0x20),
                inputLength,
                add(output, 0x20),
                32
            )
        }
        require(success, "popVerify");
        bool result = abi.decode(output, (bool));
        return result;
    }

    function deposit(
        bytes calldata blsPubKey,
        bytes calldata peerId,
        bytes calldata signature,
        address rewardAddress
    ) public payable {
        require(blsPubKey.length == 48);
        require(peerId.length == 38);
        require(signature.length == 96);

        // Verify signature as a proof-of-possession of the private key.
        bool pop = _popVerify(blsPubKey, signature);
        require(pop, "rogue key check");

        Staker storage staker = _stakersMap[blsPubKey];

        if (msg.value < minimumStake) {
            revert("stake is less than minimum stake");
        }

        _stakerKeys[msg.sender] = blsPubKey;
        staker.peerId = peerId;
        staker.rewardAddress = rewardAddress;
        staker.controlAddress = msg.sender;

        updateLatestComputedEpoch();

        Committee storage futureCommittee = _committee[
            (currentEpoch() + 2) % 3
        ];

        require(
            futureCommittee.stakerKeys.length < maximumStakers,
            "too many stakers"
        );
        require(
            futureCommittee.stakers[blsPubKey].index == 0,
            "staker already exists"
        );

        futureCommittee.totalStake += msg.value;
        futureCommittee.stakers[blsPubKey].balance = msg.value;
        futureCommittee.stakers[blsPubKey].index =
            futureCommittee.stakerKeys.length +
            1;
        futureCommittee.stakerKeys.push(blsPubKey);
    }

    function depositTopup() public payable {
        bytes storage stakerKey = _stakerKeys[msg.sender];
        require(stakerKey.length != 0, "staker does not exist");

        updateLatestComputedEpoch();

        Committee storage futureCommittee = _committee[
            (currentEpoch() + 2) % 3
        ];
        require(
            futureCommittee.stakers[stakerKey].index != 0,
            "staker does not exist"
        );
        futureCommittee.totalStake += msg.value;
        futureCommittee.stakers[stakerKey].balance += msg.value;
    }

    function unstake(uint256 amount) public {
        bytes storage stakerKey = _stakerKeys[msg.sender];
        require(stakerKey.length != 0, "staker does not exist");
        Staker storage staker = _stakersMap[stakerKey];

        updateLatestComputedEpoch();

        Committee storage futureCommittee = _committee[
            (currentEpoch() + 2) % 3
        ];

        require(
            futureCommittee.stakers[stakerKey].index != 0,
            "staker does not exist"
        );
        require(futureCommittee.stakerKeys.length > 1, "too few stakers");
        require(
            futureCommittee.stakers[stakerKey].balance >= amount,
            "amount is greater than staked balance"
        );

        if (futureCommittee.stakers[stakerKey].balance - amount == 0) {
            // Remove the staker from the future committee, because their staked amount has gone to zero.
            futureCommittee.totalStake -= amount;

            uint256 deleteIndex = futureCommittee.stakers[stakerKey].index - 1;
            uint256 lastIndex = futureCommittee.stakerKeys.length - 1;

            if (deleteIndex != lastIndex) {
                // Move the last staker in `stakerKeys` to the position of the staker we want to delete.
                bytes storage lastStakerKey = futureCommittee.stakerKeys[
                    lastIndex
                ];
                futureCommittee.stakerKeys[deleteIndex] = lastStakerKey;
                // We need to remember to update the moved staker's `index` too.
                futureCommittee.stakers[lastStakerKey].index = futureCommittee
                    .stakers[stakerKey]
                    .index;
            }

            // It is now safe to delete the final staker in the list.
            futureCommittee.stakerKeys.pop();
            delete futureCommittee.stakers[stakerKey];

            // Note that we leave the staker in `_stakersMap` forever.
        } else {
            require(
                futureCommittee.stakers[stakerKey].balance - amount >=
                    minimumStake,
                "unstaking this amount would take the validator below the minimum stake"
            );

            // Partial unstake. The staker stays in the committee, but with a reduced stake.
            futureCommittee.totalStake -= amount;
            futureCommittee.stakers[stakerKey].balance -= amount;
        }

        // Enqueue the withdrawal for this staker.
        Deque.Withdrawals storage withdrawals = staker.withdrawals;
        Withdrawal storage currentWithdrawal;
        // We know `withdrawals` is sorted by `startedAt`. We also know `block.timestamp` is monotonically
        // non-decreasing. Therefore if there is an existing entry with a `startedAt = block.timestamp`, it must be
        // at the end of the queue.
        if (
            withdrawals.length() != 0 &&
            withdrawals.back().startedAt == block.timestamp
        ) {
            // They have already made a withdrawal at this time, so grab a reference to the existing one.
            currentWithdrawal = withdrawals.back();
        } else {
            // Add a new withdrawal to the end of the queue.
            currentWithdrawal = withdrawals.pushBack();
            currentWithdrawal.startedAt = block.timestamp;
        }
        currentWithdrawal.amount += amount;
    }

    function withdraw() public {
        _withdraw(0);
    }

    function withdraw(uint256 count) public {
        _withdraw(count);
    }

    function withdrawalPeriod() public pure returns (uint256) {
        // 2 weeks
        return 2 * 7 * 24 * 60 * 60;
    }

    function _withdraw(uint256 count) internal {
        uint256 releasedAmount = 0;

        Staker storage staker = _stakersMap[_stakerKeys[msg.sender]];

        Deque.Withdrawals storage withdrawals = staker.withdrawals;
        count = (count == 0 || count > withdrawals.length())
            ? withdrawals.length()
            : count;

        while (count > 0) {
            Withdrawal storage withdrawal = withdrawals.front();
            if (withdrawal.startedAt + withdrawalPeriod() <= block.timestamp) {
                releasedAmount += withdrawal.amount;
                withdrawals.popFront();
            } else {
                // Thanks to the invariant on `withdrawals`, we know the elements are ordered by `startedAt`, so we can
                // break early when we encounter any withdrawal that isn't ready to be released yet.
                break;
            }
            count -= 1;
        }

        (bool sent, ) = msg.sender.call{value: releasedAmount}("");
        require(sent, "failed to send");
    }
}
