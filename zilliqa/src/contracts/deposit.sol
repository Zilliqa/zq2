// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

using Deque for Deque.Withdrawals;

struct Staker {
    // The index of this staker's `blsPubKey` in the `_stakerKeys` array, plus 1. 0 is used for non-existing entries.
    uint256 keyIndex;
    // Invariant: `balance >= minimumStake`
    uint256 balance;
    address rewardAddress;
    bytes peerId;
    // Invariants: Items are always sorted by `startedAt`. No two items have the same value of `startedAt`.
    Deque.Withdrawals withdrawals;
}

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
    function physicalIdx(Withdrawals storage deque, uint256 idx) private view returns (uint256) {
        uint256 physical = deque.head + idx;
        // Wrap the physical index in case it is out-of-bounds of the buffer.
        if (physical >= deque.values.length) {
            return deque.values.length - physical;
        } else {
            return physical;
        }
    }

    function length(Withdrawals storage deque) public view returns (uint256) {
        return deque.len;
    }

    // Get the element at the given logical index. Reverts if `idx >= queue.length()`.
    function get(Withdrawals storage deque, uint256 idx) public view returns (Withdrawal storage) {
        if (idx >= deque.len) {
            revert("element does not exist");
        }

        uint256 pIdx = physicalIdx(deque, idx);
        return deque.values[pIdx];
    }

    // Push an empty element to the back of the queue. Returns a reference to the new element.
    function pushBack(Withdrawals storage deque) public returns (Withdrawal storage) {
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
    function popFront(Withdrawals storage deque) public returns (Withdrawal storage) {
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
    function back(Withdrawals storage deque) public view returns (Withdrawal storage) {
        return get(deque, deque.len - 1);
    }

    // Peeks the element at the front of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function front(Withdrawals storage deque) public view returns (Withdrawal storage) {
        return get(deque, 0);
    }
}

contract Deposit {
    bytes[] _stakerKeys;
    mapping(bytes => Staker) _stakersMap;
    uint256 public totalStake;

    uint256 public _minimumStake;

    constructor(uint256 minimumStake) {
        _minimumStake = minimumStake;
    }

    function leaderFromRandomness(uint256 randomness) private view returns (bytes memory) {
        // Get a random number in the inclusive range of 0 to (totalStake - 1)
        uint256 position = randomness % totalStake;
        uint256 cummulative_stake = 0;

        for (uint256 i = 0; i < _stakerKeys.length; i++) {
            bytes storage stakerKey = _stakerKeys[i];
            Staker storage staker = _stakersMap[stakerKey];

            cummulative_stake += staker.balance;

            if (position < cummulative_stake) {
                return stakerKey;
            }
        }

        revert("Unable to select next leader");
    }

    function leader() public view returns (bytes memory) {
        return leaderFromRandomness(uint256(block.prevrandao));
    }

    function leaderAtView(uint256 viewNumber) public view returns (bytes memory) {
        uint256 randomness = uint256(keccak256(bytes.concat(bytes32(viewNumber))));
        return leaderFromRandomness(randomness);
    }

    // Temporary function to manually remove a staker. Can be called by the reward address of any staker with more than
    // 10% stake. Will be removed later in development.
    function tempRemoveStaker(bytes calldata blsPubKey) public {
        require(blsPubKey.length == 48);
        
        // Inefficient, but its fine because this is temporary.
        for (uint256 i = 0; i < _stakerKeys.length; i++) {
            bytes storage stakerKey = _stakerKeys[i];
            Staker storage staker = _stakersMap[stakerKey];

            // Check if the call is authorised.
            if (msg.sender == staker.rewardAddress && staker.balance > (totalStake / 10)) {
                // The call is authorised, so we can delete the specified staker.
                Staker storage stakerToDelete = _stakersMap[blsPubKey];

                // Delete this staker's key from `_stakerKeys`. Swap the last element in the array into the deleted position.
                bytes storage swappedStakerKey = _stakerKeys[_stakerKeys.length - 1];
                Staker storage swappedStaker = _stakersMap[swappedStakerKey];
                _stakerKeys[stakerToDelete.keyIndex - 1] = swappedStakerKey;
                swappedStaker.keyIndex = stakerToDelete.keyIndex;

                // The last element is now the element we want to delete.
                _stakerKeys.pop();

                // Reduce the total stake, but don't refund to the removed staker
                totalStake -= stakerToDelete.balance;

                // Delete the staker from `_stakersMap` too.
                delete _stakersMap[blsPubKey];

                return;
            }
        }
        revert("call must come from a reward address corresponding to a staker with more than 10% stake");
    }

    function deposit(bytes calldata blsPubKey, bytes calldata peerId, bytes calldata /* signature */, address rewardAddress) public payable {
        require(blsPubKey.length == 48);
        require(peerId.length == 38);
        // TODO: Verify signature as a proof-of-possession of the private key.

        uint256 keyIndex = _stakersMap[blsPubKey].keyIndex;
        if (keyIndex == 0) {
            // The staker will be at index `_stakerKeys.length`. We also need to add 1 to avoid the 0 sentinel value.
            _stakersMap[blsPubKey].keyIndex = _stakerKeys.length + 1;
            _stakerKeys.push(blsPubKey);
        } else {
            // TODO: Remove the following check once the verification of the BLS signature has been implemented.
            require(msg.sender == _stakersMap[blsPubKey].rewardAddress);
        }

        _stakersMap[blsPubKey].balance += msg.value;
        totalStake += msg.value;

        if (_stakersMap[blsPubKey].balance < _minimumStake) {
            revert("stake less than minimum stake");
        }

        _stakersMap[blsPubKey].rewardAddress = rewardAddress;
        _stakersMap[blsPubKey].peerId = peerId;
    }

    function withdraw(bytes calldata blsPubKey, uint256 amount) public {
        require(blsPubKey.length == 48);

        // TODO: Remove the following check once the verification of the BLS signature has been implemented.
        require(msg.sender == _stakersMap[blsPubKey].rewardAddress);

        _stakersMap[blsPubKey].balance -= amount;

        Deque.Withdrawals storage withdrawals = _stakersMap[blsPubKey].withdrawals;
        Withdrawal storage currentWithdrawal;
        if (withdrawals.back().startedAt == block.timestamp) {
            currentWithdrawal = withdrawals.back();
        } else {
            currentWithdrawal = withdrawals.pushBack();
            currentWithdrawal.startedAt = block.timestamp;
        }
        currentWithdrawal.amount += amount;
    }

    function release(bytes calldata blsPubKey) public {
        _release(blsPubKey, 0);
    }

    function release(bytes calldata blsPubKey, uint256 count) public {
        _release(blsPubKey, count);
    }

    function _release(bytes calldata blsPubKey, uint256 count) internal {
        require(blsPubKey.length == 48);

        // TODO: Remove the following check once the verification of the BLS signature has been implemented.
        require(msg.sender == _stakersMap[blsPubKey].rewardAddress);

        // 2 weeks
        uint256 unbondingPeriod = 2 * 7 * 24 * 60 * 60;

        uint256 releasedAmount = 0;

        Deque.Withdrawals storage withdrawals = _stakersMap[blsPubKey].withdrawals;
        count = (count == 0 || count > withdrawals.length()) ? withdrawals.length() : count;

        while (count > 0) {
            Withdrawal storage withdrawal = withdrawals.front();
            if (withdrawal.startedAt + unbondingPeriod <= block.timestamp) {
                releasedAmount += withdrawal.amount;
                withdrawals.popFront();
            } else {
                // Thanks to the invariant on `withdrawals`, we know the elements are ordered by `startedAt`, so
                // we can break early when we encounter any withdrawal that isn't ready to be released yet.
                break;
            }
            count -= 1;
        }

        (bool sent,) = msg.sender.call{value: releasedAmount}("");
        // TODO: Consider what to do if this fails
        require(sent, "failed to send");
    }

    function setStake(bytes calldata blsPubKey, bytes calldata peerId, address rewardAddress, uint256 amount) public {
        require(msg.sender == address(0));
        require(blsPubKey.length == 48);
        require(peerId.length == 38);

        if (amount < _minimumStake) {
            revert("stake less than minimum stake");
        }

        totalStake -= _stakersMap[blsPubKey].balance;
        _stakersMap[blsPubKey].balance = amount;
        totalStake += amount;
        _stakersMap[blsPubKey].rewardAddress = rewardAddress;
        _stakersMap[blsPubKey].peerId = peerId;
        uint256 keyIndex = _stakersMap[blsPubKey].keyIndex;
        if (keyIndex == 0) {
            // The staker will be at index `_stakerKeys.length`. We also need to add 1 to avoid the 0 sentinel value.
            _stakersMap[blsPubKey].keyIndex = _stakerKeys.length + 1;
            _stakerKeys.push(blsPubKey);
        }
    }

    function getStake(bytes calldata blsPubKey) public view returns (uint256) {
        require(blsPubKey.length == 48);

        return _stakersMap[blsPubKey].balance;
    }

    function getRewardAddress(bytes calldata blsPubKey) public view returns (address) {
        require(blsPubKey.length == 48);
        if (_stakersMap[blsPubKey].rewardAddress == address(0)) {
            revert("not staked");
        }
        return _stakersMap[blsPubKey].rewardAddress;
    }

    function getStakers() public view returns (bytes[] memory) {
        return _stakerKeys;
    }

    function getPeerId(bytes calldata blsPubKey) public view returns (bytes memory) {
        require(blsPubKey.length == 48);
        if (_stakersMap[blsPubKey].rewardAddress == address(0)) {
            revert("not staked");
        }
        return _stakersMap[blsPubKey].peerId;
    }
}
