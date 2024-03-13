// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

struct Staker {
    // The index of this staker's `blsPubKey` in the `_stakerKeys` array, plus 1. 0 is used for non-existing entries.
    uint256 keyIndex;
    uint256 balance;
    address rewardAddress;
}

contract Deposit {
    bytes[] _stakerKeys;
    mapping(bytes => Staker) _stakersMap;
    uint256 totalStake;

    uint256 public minimumStake = 32_000_000_000_000_000_000;

    function deposit(bytes calldata blsPubKey, bytes calldata /* signature */, address rewardAddress) public payable {
        require(blsPubKey.length == 48);

        // TODO: Verify signature as a proof-of-possession of the private key.

        _stakersMap[blsPubKey].balance += msg.value;
        totalStake += msg.value;
        _stakersMap[blsPubKey].rewardAddress = rewardAddress;
        uint256 keyIndex = _stakersMap[blsPubKey].keyIndex;
        if (keyIndex == 0) {
            // The staker will be at index `_stakerKeys.length`. We also need to add 1 to avoid the 0 sentinel value.
            _stakersMap[blsPubKey].keyIndex = _stakerKeys.length + 1;
            _stakerKeys.push(blsPubKey);
        }
    }

    function setStake(bytes calldata blsPubKey, address rewardAddress, uint256 amount) public {
        require(msg.sender == address(0));
        require(blsPubKey.length == 48);

        totalStake -= _stakersMap[blsPubKey].balance;
        _stakersMap[blsPubKey].balance = amount;
        totalStake += amount;
        _stakersMap[blsPubKey].rewardAddress = rewardAddress;
        uint256 keyIndex = _stakersMap[blsPubKey].keyIndex;
        if (keyIndex == 0) {
            // The staker will be at index `_stakerKeys.length`. We also need to add 1 to avoid the 0 sentinel value.
            _stakersMap[blsPubKey].keyIndex = _stakerKeys.length + 1;
            _stakerKeys.push(blsPubKey);
        }
    }

    function getStake(bytes calldata blsPubKey) public view returns (uint256) {
        require(blsPubKey.length == 48);

        if (_stakersMap[blsPubKey].balance >= minimumStake) {
            return _stakersMap[blsPubKey].balance;
        } else {
            return 0;
        }
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
}
