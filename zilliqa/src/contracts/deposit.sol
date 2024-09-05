// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

struct Staker {
    // The index of this staker's `blsPubKey` in the `_stakerKeys` array, plus 1. 0 is used for non-existing entries.
    uint256 keyIndex;
    // Invariant: `balance >= minimumStake`
    uint256 balance;
    address rewardAddress;
    bytes peerId;
}

contract Deposit {
    bytes[] _stakerKeys;
    mapping(bytes => Staker) _stakersMap;
    uint256 public totalStake;

    uint256 public _minimumStake;
    uint256 public _maximumStakers;

    constructor(uint256 minimumStake, uint256 maximumStakers) {
        _minimumStake = minimumStake;
        _maximumStakers = maximumStakers;
    }

    function leaderFromRandomness(
        uint256 randomness
    ) private view returns (bytes memory) {
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

    function leaderAtView(
        uint256 viewNumber
    ) public view returns (bytes memory) {
        uint256 randomness = uint256(
            keccak256(bytes.concat(bytes32(viewNumber)))
        );
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
            if (
                msg.sender == staker.rewardAddress &&
                staker.balance > (totalStake / 10)
            ) {
                // The call is authorised, so we can delete the specified staker.
                Staker storage stakerToDelete = _stakersMap[blsPubKey];

                // Delete this staker's key from `_stakerKeys`. Swap the last element in the array into the deleted position.
                bytes storage swappedStakerKey = _stakerKeys[
                    _stakerKeys.length - 1
                ];
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
        revert(
            "call must come from a reward address corresponding to a staker with more than 10% stake"
        );
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

        require(_stakerKeys.length < _maximumStakers, "too many stakers");

        // Verify signature as a proof-of-possession of the private key.
        bool pop = _popVerify(blsPubKey, signature);
        require(pop, "rogue key check");

        uint256 keyIndex = _stakersMap[blsPubKey].keyIndex;
        if (keyIndex == 0) {
            // The staker will be at index `_stakerKeys.length`. We also need to add 1 to avoid the 0 sentinel value.
            _stakersMap[blsPubKey].keyIndex = _stakerKeys.length + 1;
            _stakerKeys.push(blsPubKey);
        }

        _stakersMap[blsPubKey].balance += msg.value;
        totalStake += msg.value;

        if (_stakersMap[blsPubKey].balance < _minimumStake) {
            revert("stake less than minimum stake");
        }

        _stakersMap[blsPubKey].rewardAddress = rewardAddress;
        _stakersMap[blsPubKey].peerId = peerId;
    }

    function setStake(
        bytes calldata blsPubKey,
        bytes calldata peerId,
        address rewardAddress,
        uint256 amount
    ) public {
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
        return _stakerKeys;
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
