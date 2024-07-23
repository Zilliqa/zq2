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

    function bls12_g1map(
        bytes memory pubkey
    ) private view returns (bytes memory) {
        bytes16 zero = 0; // 16-bytes padding 48b->64b.
        bytes memory input = abi.encodePacked(zero, pubkey);
        bytes memory output = new bytes(128);
        bool success;
        assembly {
            success := staticcall(
                gas(),
                0x12,
                add(input, 0x20),
                64,
                add(output, 0x20),
                128
            )
        }
        require(success, "bls12_fp_map_g1");
        return output;
    }

    function bls12_g2map(
        bytes memory in96
    ) private view returns (bytes memory) {
        bytes memory input = new bytes(128);
        for (uint i = 0; i < 48; i++) {
            // slice inputs
            input[16 + i] = in96[i];
            input[16 + 64 + i] = in96[48 + i];
        }
        bytes memory output = new bytes(256);
        bool success;
        assembly {
            success := staticcall(
                gas(),
                0x13,
                add(input, 0x20),
                128,
                add(output, 0x20),
                256
            )
        }
        require(success, "bls12_fp2_map_g2");
        return output;
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

        // Test vectors from EIP.
        // bytes
        //     memory inputG2 = hex"07355d25caf6e7f2f0cb2812ca0e513bd026ed09dda65b177500fa31714e09ea0ded3a078b526bed3307f804d4b93b0402829ce3c021339ccb5caf3e187f6370e1e2a311dec9b75363117063ab2015603ff52c3d3b98f19c2f65575e99e8b78c";
        // bytes memory R = bls12_g2map(inputG2);
        // bytes
        //     memory checkG2 = hex"0000000000000000000000000000000000e7f4568a82b4b7dc1f14c6aaa055edf51502319c723c4dc2688c7fe5944c213f510328082396515734b6612c4e7bb700000000000000000000000000000000126b855e9e69b1f691f816e48ac6977664d24d99f8724868a184186469ddfd4617367e94527d4b74fc86413483afb35b000000000000000000000000000000000caead0fd7b6176c01436833c79d305c78be307da5f6af6c133c47311def6ff1e0babf57a0fb5539fce7ee12407b0a42000000000000000000000000000000001498aadcf7ae2b345243e281ae076df6de84455d766ab6fcdaad71fab60abb2e8b980a440043cd305db09d283c895e3d";
        // require(keccak256(R) == keccak256(checkG2), "keccakG2");

        // bytes
        // memory inputG1 = hex"147e1ed29f06e4c5079b9d14fc89d2820d32419b990c1c7bb7dbea2a36a045124b31ffbde7c99329c05c559af1c6cc82";
        // bytes memory xP = bls12_g1map(inputG1);
        // bytes
        //     memory checkG1 = hex"00000000000000000000000000000000009769f3ab59bfd551d53a5f846b9984c59b97d6842b20a2c565baa167945e3d026a3755b6345df8ec7e6acb6868ae6d000000000000000000000000000000001532c00cf61aa3d0ce3e5aa20c3b531a2abd2c770a790a2613818303c6b830ffc0ecf6c357af3317b9575c567f11cd2c";
        // require(keccak256(xP) == keccak256(checkG1), "keccakG1");

        // bytes
        //     memory a1 = hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
        // bytes
        //     memory a2 = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801000000000000000000000000000000000606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be";
        // bytes
        //     memory b1 = hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb0000000000000000000000000000000008b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
        // bytes
        //     memory b2 = hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";
        // bool checkPC = bls12_pairing_check(a1, a2, b1, b2);
        // require(checkPC);

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
