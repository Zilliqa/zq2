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
                151000, // 2 * 43000 + 65000
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

    bytes constant DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"; // FIXME: Use the POP tag instead

    // https://github.com/supranational/blst/blob/52cc60d78591a56abb2f3d0bd1cdafc6ba242997/src/e1.c#L34
    bytes constant NEG_G1_X =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
    bytes constant NEG_G1_Y =
        hex"00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";
    // https://github.com/supranational/blst/blob/52cc60d78591a56abb2f3d0bd1cdafc6ba242997/src/e2.c#L49
    bytes constant NEG_G2_X0 =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
    bytes constant NEG_G2_X1 =
        hex"0000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e";
    bytes constant NEG_G2_Y0 =
        hex"000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa";
    bytes constant NEG_G2_Y1 =
        hex"0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";
    bytes16 constant zero16 = 0;

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
        // let a = Self::hash_to_point::<B, C>(msg, dst);
        G2Point memory aG = hasher.hashToCurveG2(blsPubKey, DST); // PubKey is the message.
        bytes memory a = bytes.concat(aG.x, aG.x_I, aG.y, aG.y_I);
        require(a.length == 256, "a.length");

        // let generator = -Self::PublicKey::generator();
        bytes memory neg_g = bytes.concat(NEG_G1_X, NEG_G1_Y); // TODO: Hard-code this.
        require(neg_g.length == 128, "neg_g.length");

        // TODO: octet_to_point_E1(pk);
        // TODO: octet_to_point_E2(sig);

        // if Self::pairing(&[(a, pk), (sig, generator)]) - (G2, G1)
        //     .is_identity()

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
