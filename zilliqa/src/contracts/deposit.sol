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
        if (deque.values.length >= physical) {
            return deque.values.length - physical;
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
        return get(deque, deque.len - 1);
    }

    // Peeks the element at the front of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function front(
        Withdrawals storage deque
    ) internal view returns (Withdrawal storage) {
        return get(deque, 0);
    }
}

using Deque for Deque.Withdrawals;

struct Committee {
    // Invariant: Equal to the sum of `balances`
    uint256 totalStake;
    bytes[] stakers;
    // Invariant: for b in balances: `b >= minimumStake`
    uint256[] balances;
}

struct Staker {
    // The address used for authenticating requests from this staker to the deposit contract.
    // Invariant: `controlAddress != address(0)`.
    address controlAddress;
    // The address which rewards for this staker will be sent to.
    address rewardAddress;
    // The index of this staker's `blsPubKey` in the `Committee`'s `stakers` array. Set to -1 if not currently part of the committee.
    int256 keyIndex;
    // libp2p peer ID, corresponding to the staker's `blsPubKey`
    bytes peerId;
    // Invariants: Items are always sorted by `startedAt`. No two items have the same value of `startedAt`.
    Deque.Withdrawals withdrawals;
}

contract Deposit {
    // The committee in the current epoch and the 2 epochs following it. The value for the current epoch
    // is stored at index (currentEpoch() % 3).
    Committee[3] _committee;

    function internalCommittee() public view returns (Committee[3] memory) {
        return _committee;
    }

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

    uint64 public blocksPerEpoch; // TODO - get this from shard contract instead!

    constructor(
        uint256 _minimumStake,
        uint256 _maximumStakers,
        uint64 _blocksPerEpoch
    ) {
        minimumStake = _minimumStake;
        maximumStakers = _maximumStakers;
        blocksPerEpoch = _blocksPerEpoch;
        latestComputedEpoch = currentEpoch();
    }

    function leaderFromRandomness(
        uint256 randomness
    ) private view returns (bytes memory) {
        // Get a random number in the inclusive range of 0 to (totalStake - 1)
        uint256 position = randomness % committee().totalStake;
        uint256 cummulative_stake = 0;

        // TODO: Consider binary search for performance. Or consider an alias method for O(1) performance.
        for (uint256 i = 0; i < committee().stakers.length; i++) {
            bytes memory stakerKey = committee().stakers[i];
            uint256 stakedBalance = committee().balances[i];

            cummulative_stake += stakedBalance;

            if (position < cummulative_stake) {
                return stakerKey;
            }
        }

        revert("Unable to select next leader");
    }

    function leader() public view returns (bytes memory) {
        return leaderFromRandomness(uint256(block.prevrandao));
    }

    function leaderAtView(
        uint256 viewNumber
    ) public view returns (bytes memory) {
        uint256 randomness = uint256(
            keccak256(bytes.concat(bytes32(viewNumber)))
        );
        return leaderFromRandomness(randomness);
    }

    function committee() public view returns (Committee memory) {
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

    function getStakers() public view returns (bytes[] memory) {
        return committee().stakers;
    }

    function getStake(bytes calldata blsPubKey) public view returns (uint256) {
        require(blsPubKey.length == 48);

        return committee().balances[uint(_stakersMap[blsPubKey].keyIndex)];
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

    function currentEpoch() public view returns (uint64) {
        return uint64(block.number / blocksPerEpoch);
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
            // i in (1..=2) {1, 2}
            for (
                uint64 i = latestComputedEpoch + 1;
                i <= currentEpoch() + 2 && i < latestComputedEpoch + 3;
                i++
            ) {
                _committee[i % 3] = latestComputedCommittee;
            }

            latestComputedEpoch = currentEpoch() + 2;
        }
    }

    // TODO: REMOVE AND SET IN CONSTRUCTOR INSTEAD
    function setStake(
        bytes calldata blsPubKey,
        bytes calldata peerId,
        address rewardAddress,
        address controlAddress,
        uint256 amount
    ) public {
        require(blsPubKey.length == 48);
        require(peerId.length == 38);

        require(
            committee().stakers.length < maximumStakers,
            "too many stakers"
        );

        Staker storage staker = _stakersMap[blsPubKey];
        // This must be a new staker, meaning the control address must be zero.
        // TODO: Separate method for topping up existing validator.
        require(staker.controlAddress == address(0), "staker already exists");

        if (amount < minimumStake) {
            revert("stake is less than minimum stake");
        }

        _stakerKeys[controlAddress] = blsPubKey;
        staker.peerId = peerId;
        staker.controlAddress = controlAddress;
        staker.rewardAddress = rewardAddress;

        Committee storage currentCommittee = _committee[currentEpoch() % 3];
        currentCommittee.totalStake += amount;
        staker.keyIndex = int(currentCommittee.stakers.length);
        currentCommittee.stakers.push(blsPubKey);
        currentCommittee.balances.push(amount);
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

        require(
            committee().stakers.length < maximumStakers,
            "too many stakers"
        );

        // Verify signature as a proof-of-possession of the private key.
        bool pop = _popVerify(blsPubKey, signature);
        require(pop, "rogue key check");

        Staker storage staker = _stakersMap[blsPubKey];
        // This must be a new staker, meaning the control address must be zero.
        // TODO: Separate method for topping up existing validator.
        require(staker.controlAddress == address(0), "staker already exists");

        if (msg.value < minimumStake) {
            revert("stake is less than minimum stake");
        }

        _stakerKeys[msg.sender] = blsPubKey;
        staker.peerId = peerId;
        staker.controlAddress = msg.sender;
        staker.rewardAddress = rewardAddress;

        updateLatestComputedEpoch();

        Committee storage futureCommittee = _committee[
            (currentEpoch() + 2) % 3
        ];
        futureCommittee.totalStake += msg.value;
        staker.keyIndex = int(futureCommittee.stakers.length);
        futureCommittee.stakers.push(blsPubKey);
        futureCommittee.balances.push(msg.value);
    }

    function depositTopup() public payable {
        bytes storage stakerKey = _stakerKeys[msg.sender];
        require(stakerKey.length != 0, "staker does not exist");
        Staker storage staker = _stakersMap[stakerKey];

        updateLatestComputedEpoch();

        Committee storage futureCommittee = _committee[
            (currentEpoch() + 2) % 3
        ];
        futureCommittee.totalStake += msg.value;
        futureCommittee.balances[uint(staker.keyIndex)] += msg.value;
    }

    function unstake(uint256 amount) public {
        bytes storage stakerKey = _stakerKeys[msg.sender];
        require(stakerKey.length != 0, "staker does not exist");
        Staker storage staker = _stakersMap[stakerKey];

        updateLatestComputedEpoch();

        Committee storage futureCommittee = _committee[
            (currentEpoch() + 2) % 3
        ];

        if (
            futureCommittee.balances[uint(staker.keyIndex)] - amount <
            minimumStake
        ) {
            // Remove the staker from the future committee, because their staked amount has gone under the minimum
            // stake. Note that we unstake their full balance, which might be more than the `amount` they passed in.
            amount = futureCommittee.balances[uint(staker.keyIndex)];
            futureCommittee.totalStake -= amount;

            // Delete this staker. We need to delete it in 3 places:
            // 1. `futureCommittee.stakers`
            // 2. `futureCommittee.balances`
            // 3. `_stakersMap`

            // First move the last staker into the position of the staker we want to delete. This needs to be done in
            // `futureCommittee.stakers` and `futureCommittee.balances`. We also need to update the `keyIndex` of the
            // last staker to point to its new index.
            bytes storage lastStakerKey = futureCommittee.stakers[
                futureCommittee.stakers.length - 1
            ];
            uint256 lastStakerBalance = futureCommittee.balances[
                futureCommittee.balances.length - 1
            ];
            Staker storage lastStaker = _stakersMap[lastStakerKey];
            futureCommittee.stakers[uint(staker.keyIndex)] = lastStakerKey;
            futureCommittee.balances[uint(staker.keyIndex)] = lastStakerBalance;
            lastStaker.keyIndex = staker.keyIndex;

            // Now the last staker has been moved to a new position, we can safely delete the final element from both
            // arrays.
            futureCommittee.stakers.pop();
            futureCommittee.balances.pop();

            // We can finally delete the origin staker from `_stakersMap` too.
            delete _stakersMap[stakerKey];
        } else {
            futureCommittee.totalStake -= amount;
            futureCommittee.balances[uint(staker.keyIndex)] -= amount;
        }

        // Enqueue the withdrawal for this staker.
        Deque.Withdrawals storage withdrawals = staker.withdrawals;
        Withdrawal storage currentWithdrawal;
        // We know `withdrawals` is sorted by `startedAt`. We also know `block.timestamp` is monotonically
        // non-decreasing. Therefore if there is an existing entry with a `startedAt = block.timestamp`, it must be
        // at the end of the queue.
        if (withdrawals.back().startedAt == block.timestamp) {
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

    function _withdraw(uint256 count) internal {
        // 2 weeks
        uint256 unbondingPeriod = 2 * 7 * 24 * 60 * 60;

        uint256 releasedAmount = 0;

        Staker storage staker = _stakersMap[_stakerKeys[msg.sender]];

        Deque.Withdrawals storage withdrawals = staker.withdrawals;
        count = (count == 0 || count > withdrawals.length())
            ? withdrawals.length()
            : count;

        while (count > 0) {
            Withdrawal storage withdrawal = withdrawals.front();
            if (withdrawal.startedAt + unbondingPeriod <= block.timestamp) {
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
