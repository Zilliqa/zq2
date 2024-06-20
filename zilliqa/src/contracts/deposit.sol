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
    uint256 totalStake;

    uint256 public _minimumStake;

    constructor(uint256 minimumStake) {
        _minimumStake = minimumStake;
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

                // Delete this staker's key from `_stakerKeys`. Swap the last element in the array into the deleted
                // elements position.
                _stakerKeys[stakerToDelete.keyIndex - 1] = _stakerKeys[_stakerKeys.length - 1];
                // The last element is now the element we want to delete.
                _stakerKeys.pop();

                // Reduce the total stake
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
