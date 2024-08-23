// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

// Implementation of a circular queue/buffer of validator public keys
    struct Value {
        bytes key;
        uint256 amount;
    }

    struct KeysQueue {
        // Validator keys
        Value[] values;
        // The physical index of the first element, if it exists. If `len == 0`, the value of `head` is unimportant.
        uint256 head;
        // The logical number of elements in the buffer.
        uint256 len;
    }

    // Returns the physical index of an element, given its logical index.
    function physicalIdx(KeysQueue storage queue, uint256 idx) view returns (uint256) {
        uint256 physical = queue.head + idx;
        // Wrap the physical index in case it is out-of-bounds of the buffer.
        if (physical >= queue.values.length) {
            return queue.values.length - physical;
        } else {
            return physical;
        }
    }

    function length(KeysQueue storage queue) view returns (uint256) {
        return queue.len;
    }

    // Get the element at the given logical index. Reverts if `idx >= queue.length()`.
    function get(KeysQueue storage queue, uint256 idx) view returns (Value storage) {
        if (idx >= queue.len) {
            revert("element does not exist");
        }

        uint256 pIdx = physicalIdx(queue, idx);
        return queue.values[pIdx];
    }

    // Push an empty element to the back of the queue. Returns a reference to the new element.
    function pushBack(KeysQueue storage queue) returns (Value storage) {
        // Add more space in the buffer if it is full.
        if (queue.len == queue.values.length) {
            queue.values.push();
        }

        uint256 idx = physicalIdx(queue, queue.len);
        queue.len += 1;

        return queue.values[idx];
    }

    // Pop an element from the front of the queue. Note that this returns a reference to the element in storage. This
    // means that further mutations of the queue may invalidate the returned element. Do not use this return value
    // after calling any other mutations on the queue.
    function popFront(KeysQueue storage queue) returns (Value storage) {
        if (queue.len == 0) {
            revert("queue is empty");
        }

        uint256 oldHead = queue.head;
        queue.head = physicalIdx(queue, 1);
        queue.len -= 1;
        return queue.values[oldHead];
    }

using {length, get, pushBack, popFront} for KeysQueue;

enum Status { Pending, Active, Suspended, Slashed }

struct Staker {
    // Invariant: `stakedBalance >= minimumStake`
    uint256 stakedBalance;
    // Invariant: `unstakingBalance <= stakedBalance`
    uint256 unstakingBalance;
    uint256 freeBalance;
    // Invariant: `controlAddress != 0`. Usable as a sentinel value to check existence of the validator.
    address controlAddress; 
    // May be zero. Otherwise, may be equal to controlAddress.
    address rewardAddress;
    // The index of this staker's `blsPubKey` in either `committeeKeys` array. Set to -1 if not currently part of the committee.
    int256 keyIndex;
    // libp2p ID, matching the staker's blsPubKey
    bytes peerId;
    Status status;
}

contract Deposit {
    // Wait time for changes. When a deposit/withdraw request is made on epoch `n`,
    // it will actualise on epoch `n + WAIT_EPOCHS`.
    // Set to 2, that means that there will be a minimum of one full epoch of wait
    // time between changes, which avoids race conditions with finalising blocks
    // at the end of one epoch and the committee set changing immediately.
    uint8 constant WAIT_EPOCHS = 2; // epochs

    // using RingBuffer for RingBuffer.KeysQueue;

    // All stakers
    mapping(bytes => Staker) _stakersMap;
    // Mapping from control address to blsPubKey
    mapping(address => bytes) _stakerKeys;
    // Active stakers
    bytes[] committeeKeys;

    KeysQueue[WAIT_EPOCHS] pendingQueues;
    KeysQueue[WAIT_EPOCHS] unstakingQueues;
    KeysQueue kickQueue; // only one queue, as all nodes queued for kicking (slashing or suspending) get processed ASAP in the next epoch

    uint256 public totalStake;
    uint256 public minimumStake;
    uint256 public maximumStakers;

    uint64 public blocksPerEpoch; // TODO - get this from shard contract instead!

    uint64 public headProcessedEpoch;

    modifier isStaker() {
        bytes storage blsPubKey = _stakerKeys[msg.sender];
        if (blsPubKey.length == 0) {
            revert("Sender address is not a validator.");
        }
        if (_stakersMap[blsPubKey].controlAddress != msg.sender) {
            revert("Sender address matches a known pubkey, but validator with pubkey does not match the sender address - data inconsistency");
        }
        _;
    }

    constructor(uint256 _minimumStake, uint256 _maximumStakers, uint64 _blocksPerEpoch) {
        minimumStake = _minimumStake;
        blocksPerEpoch = _blocksPerEpoch;
        maximumStakers = _maximumStakers;
    }

    function leaderFromRandomness(
        uint256 randomness
    ) private view returns (bytes memory) {
        // Get a random number in the inclusive range of 0 to (totalStake - 1)
        uint256 position = randomness % totalStake;
        uint256 cummulative_stake = 0;

        for (uint256 i = 0; i < committeeKeys.length; i++) {
            bytes storage stakerKey = committeeKeys[i];
            Staker storage staker = _stakersMap[stakerKey];

            cummulative_stake += staker.stakedBalance;

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

    // keep in-sync with zilliqa/src/precompiles.rs
    function _popVerify(
        bytes memory pubkey,
        bytes memory signature
    ) private view returns (bool) {
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

        require(committeeKeys.length < maximumStakers, "too many stakers");

        // Verify signature as a proof-of-possession of the private key.
        bool pop = _popVerify(blsPubKey, signature);
        require(pop, "rogue key check");

        // If staker info isn't stored yet, do so
        // peerId is guaranteed to be non-zero for all stakers
        if (_stakersMap[blsPubKey].controlAddress == address(0)) {
            // Initial deposit on staker creation must be above minimal
            if (msg.value < minimumStake) {
                revert("Initial stake is less than minimum stake");
            }

            _stakersMap[blsPubKey].rewardAddress = rewardAddress;
            _stakersMap[blsPubKey].controlAddress = msg.sender;
            _stakersMap[blsPubKey].peerId = peerId;
            _stakersMap[blsPubKey].keyIndex = -1;
            _stakersMap[blsPubKey].status = Status.Pending; // Will be already implicitly initialised to this; explicit assignment for clarity
            _stakerKeys[msg.sender] = blsPubKey;
        }

        queueNewDeposit(blsPubKey, msg.value);
    }

    function depositTopup() public payable isStaker() {
        bytes memory blsPubKey = _stakerKeys[msg.sender];
        queueNewDeposit(blsPubKey, msg.value);
    }

    function queueNewDeposit(bytes memory blsPubKey, uint256 amount) private {
        Value storage newDeposit = pendingQueues[currentQueueIndex()].pushBack();
        newDeposit.key = blsPubKey;
        newDeposit.amount = amount;
    }

    function unstake(
        uint256 amount
    ) public isStaker() {
        bytes storage blsPubKey = _stakerKeys[msg.sender];

        uint256 stakedBalance = _stakersMap[blsPubKey].stakedBalance - _stakersMap[blsPubKey].unstakingBalance;
        if (amount > stakedBalance) {
            revert("Cannot unstake more than current validator staked balance.");
        }
        _stakersMap[blsPubKey].unstakingBalance += amount;

        Value storage newUnstaking = unstakingQueues[currentQueueIndex()].pushBack();
        newUnstaking.key = blsPubKey;
        newUnstaking.amount = amount;
    }

    function withdrawFunds(
        uint256 amount
    ) public isStaker() {
        bytes storage blsPubKey = _stakerKeys[msg.sender];
        if (amount > _stakersMap[blsPubKey].freeBalance) {
            revert("Attempting to withdraw more than the available free balance.");
        }
        _stakersMap[blsPubKey].freeBalance -= amount;
        (bool sent, bytes memory _data) = payable(_stakersMap[blsPubKey].controlAddress).call{value: amount}("");
        require(sent, "Unable to transfer balance");
    }

    function suspend() public isStaker() {
        bytes storage blsPubKey = _stakerKeys[msg.sender];
        if (_stakersMap[blsPubKey].status == Status.Slashed) {
            revert("A slashed validator cannot self-suspend.");
        }

        // Note: we immediately set the validator status to suspended here.
        // This is very generous to the validators: they can simply pause operation at any point, with no penalty.
        // An alternative would be to keep the validator Active. Then it would be removed from consensus at the
        // next epoch boundary (a fast-track compared to simply withdrawing all stake, which would take up to 2 epochs),
        // but would remain liable for liveness until then.
        _stakersMap[blsPubKey].status = Status.Suspended;

        Value storage newSuspension = kickQueue.pushBack();
        newSuspension.key = blsPubKey;
        // no associated amount
    }

    function eject(
        bytes calldata blsPubKey,
        uint256 slashAmount
    ) public isStaker() {
        bytes storage callerKey = _stakerKeys[msg.sender];
        Staker storage caller = _stakersMap[callerKey];

        // Check if the call is authorised.
        if (caller.stakedBalance < (totalStake / 10)) {
            revert(
                "call must come from a reward address corresponding to a staker with more than 10% stake"
            );
        }

        // set status to slashed, put into kickqueue for next epoch
        _stakersMap[blsPubKey].status = Status.Slashed;
        // If a validator is not currently in the committee and has status == Slashed,
        // it should not be possible for it to get into the committee in any way.
        // Thus we only bother queueing a kick if it's currently in the committee.
        if (_stakersMap[blsPubKey].keyIndex >= 0) {
            Value storage ejection = kickQueue.pushBack();
            ejection.key = blsPubKey;
            ejection.amount = slashAmount;
        }
    }

    function swapRemoveValidator(uint index) private {
        _stakersMap[committeeKeys[index]].keyIndex = -1;
        if (index != committeeKeys.length - 1) {
            bytes storage lastValidatorKey = committeeKeys[committeeKeys.length - 1];
            committeeKeys[index] = lastValidatorKey;
            _stakersMap[lastValidatorKey].keyIndex = int(index);
        }
        committeeKeys.pop();
    }


    function currentEpoch() public view returns (uint64) {
        return uint64(block.number / blocksPerEpoch); // TODO - take the value from the shard contract rather than storing it locally
    }

    function currentQueueIndex() private view returns (uint8) {
        return uint8(currentEpoch() % WAIT_EPOCHS);
    }

    function tickEpoch() public {
        // if current epoch has already been processed, exit
        if (headProcessedEpoch >= currentEpoch()) {
            return;
        }

        uint8 queueIndex = currentQueueIndex();

        // Process pending queue for this epoch
        for (uint i = 0; i < pendingQueues[queueIndex].length(); ++i) {
            Value storage newDeposit = pendingQueues[queueIndex].popFront();
            _stakersMap[newDeposit.key].stakedBalance += newDeposit.amount;
            totalStake += newDeposit.amount;
            // If the validator wasn't already active (or suspended or slashed), activate it
            if (_stakersMap[newDeposit.key].status == Status.Pending) {
                _stakersMap[newDeposit.key].status = Status.Active;
                _stakersMap[newDeposit.key].keyIndex = int(committeeKeys.length);
                committeeKeys.push(newDeposit.key);
            }
        }

        // Process unstakings queue for this epoch
        for (uint i = 0; i < unstakingQueues[queueIndex].length(); ++i) {
            Value storage unstaking = unstakingQueues[queueIndex].popFront();
            _stakersMap[unstaking.key].stakedBalance -= unstaking.amount;
            _stakersMap[unstaking.key].unstakingBalance -= unstaking.amount;
            _stakersMap[unstaking.key].freeBalance += unstaking.amount;
            totalStake -= unstaking.amount;

            // If the validator's stakedBalance is now below minimum stake, suspend it
            if (_stakersMap[unstaking.key].stakedBalance < minimumStake && _stakersMap[unstaking.key].status == Status.Active) {
                _stakersMap[unstaking.key].status = Status.Suspended;
                swapRemoveValidator(uint(_stakersMap[unstaking.key].keyIndex)); // should be safe, because it should not be possible for a validator to be Active without having a positive keyIndex
            }
        }

        // Process kick queue - suspensions (voluntary, and for liveness violations) and slashings (for consensus violations)
        for (uint i = 0; i < kickQueue.length(); ++i) {
            Value storage kick = kickQueue.popFront();
            Staker storage staker = _stakersMap[kick.key];
            // Remove the staker from the total stake and the active committee
            totalStake -= staker.stakedBalance;
            // Only remove the staker from the committee if we know it's in it currently
            // There are edge cases where it may not be necessary - e.g. if a withdrawal is processed on the same epoch as a slash/suspend, it will already have been removed just above
            if (staker.keyIndex >= 0) {
                swapRemoveValidator(uint(staker.keyIndex));
            }

            // Apply penalty, if any (might be 0 e.g. for voluntary suspension)
            // TODO: collect these rewards somewhere? Right now they're effectively burned
            staker.stakedBalance -= kick.amount;
            // If currently Active (in the case of a delayed voluntary suspension), ensure it's suspended
            // A slashed staker will already have its status set
            if (staker.status == Status.Active) {
                staker.status = Status.Suspended;
            }
        }

        // Lastly, update last processed epoch number
        headProcessedEpoch = currentEpoch();
    }

    function setStake(
        bytes calldata blsPubKey,
        bytes calldata peerId,
        address rewardAddress,
        address controlAddress,
        uint256 amount
    ) public {
        require(msg.sender == address(0));
        require(blsPubKey.length == 48);
        require(peerId.length == 38);

        if (amount < minimumStake) {
            revert("stake less than minimum stake");
        }

        Staker storage staker = _stakersMap[blsPubKey];

        if (
            staker.controlAddress != address(0) && // staker exists...
                staker.keyIndex >= 0 // ...and is in the committee
        ) {
            // then we remove its stake (before adding the new stake amount below)
            totalStake -= staker.stakedBalance;
        } else {
            // else, we add it to the committee
            staker.keyIndex = int(committeeKeys.length);
            committeeKeys.push(blsPubKey);
        }
        staker.stakedBalance = amount;
        totalStake += amount;
        staker.rewardAddress = rewardAddress;
        staker.controlAddress = controlAddress;
        staker.peerId = peerId;
        staker.status = Status.Active;
        _stakerKeys[controlAddress] = blsPubKey;
    }

    function getStake(bytes calldata blsPubKey) public view returns (uint256) {
        require(blsPubKey.length == 48);

        return _stakersMap[blsPubKey].stakedBalance;
    }

    function getRewardAddress(
        bytes calldata blsPubKey
    ) public view returns (address) {
        require(blsPubKey.length == 48);
        if (_stakersMap[blsPubKey].rewardAddress == address(0)) {
            revert("not staked");
        }
        return _stakersMap[blsPubKey].rewardAddress;
    }

    function getStakers() public view returns (bytes[] memory) {
        return committeeKeys;
    }

    function getPeerId(
        bytes calldata blsPubKey
    ) public view returns (bytes memory) {
        require(blsPubKey.length == 48);
        if (_stakersMap[blsPubKey].rewardAddress == address(0)) {
            revert("not staked");
        }
        return _stakersMap[blsPubKey].peerId;
    }
}
