// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;
import "./hash_to_curve.sol";

struct Staker {
    // The index of this staker's `blsPubKey` in the `_stakerKeys` array, plus 1. 0 is used for non-existing entries.
    uint256 keyIndex;
    // Invariant: `balance >= minimumStake`
    uint256 balance;
    address rewardAddress;
    bytes peerId;
}

contract Deposit {
    HashToCurve public hasher;
    bytes[] _stakerKeys;
    mapping(bytes => Staker) _stakersMap;
    uint256 public totalStake;

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

    function bls12_pairing_check(
        bytes memory a128,
        bytes memory a256,
        bytes memory b128,
        bytes memory b256
    ) private view returns (bool) {
        bytes memory input = abi.encodePacked(a128, a256, b128, b256);
        bytes memory output = new bytes(32);
        bool success;
        assembly {
            success := staticcall(
                gas(),
                0x11,
                add(input, 0x20),
                768,
                add(output, 0x20),
                32
            )
        }
        require(success, "bls12_pairing_check");
        return output[31] == 0x01;
    }

    bytes constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    // test vectors from library
    bytes constant HASH_TO_G1_DST =
        "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    bytes constant expected_P_x =
        hex"00000000000000000000000000000000052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1";
    bytes constant expected_P_y =
        hex"0000000000000000000000000000000008ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265";

    function deposit(
        bytes calldata blsPubKey,
        bytes calldata peerId,
        bytes calldata signature,
        address rewardAddress
    ) public payable {
        require(blsPubKey.length == 48);
        require(peerId.length == 38);
        require(signature.length == 96);
        // TODO: Verify signature as a proof-of-possession of the private key.

        hasher = new HashToCurve();
        G1Point memory result = hasher.hashToCurveG1("", HASH_TO_G1_DST);
        require(keccak256(result.x) == keccak256(expected_P_x), "Px");
        require(keccak256(result.y) == keccak256(expected_P_y), "Py");

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
