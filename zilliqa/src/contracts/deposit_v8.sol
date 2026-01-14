// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.28;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Deque, Withdrawal} from "./utils/deque_v2.sol";

using Deque for Deque.Withdrawals;

/// Argument has unexpected length
/// @param argument name of argument
/// @param required expected length
error UnexpectedArgumentLength(string argument, uint256 required);

/// Message sender does not control the key it is attempting to modify
error Unauthorised();
/// Maximum number of stakers has been reached
error TooManyStakers();
/// Key already staked
error KeyAlreadyStaked();
/// Key is not staked
error KeyNotStaked();
/// Stake amount less than minimum
error StakeAmountTooLow();

/// Proof of possession verification failed
error RogueKeyCheckFailed();

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
    // The address whose key with which validators sign cross-chain events
    address signingAddress;
}

contract Deposit is UUPSUpgradeable {
    // Emitted to inform that a new staker identified by `blsPubKey`
    // is going to be added to the committee `atFutureBlock`, increasing
    // the total stake by `newStake`
    event StakerAdded(bytes blsPubKey, uint256 atFutureBlock, uint256 newStake);

    // Emitted to inform that the staker identified by `blsPubKey`
    // is going to be removed from the committee `atFutureBlock`
    event StakerRemoved(bytes blsPubKey, uint256 atFutureBlock);

    // Emitted to inform that the deposited stake of the staker
    // identified by `blsPubKey` is going to change to `newStake`
    // at `atFutureBlock`
    event StakeChanged(
        bytes blsPubKey,
        uint256 atFutureBlock,
        uint256 newStake
    );

    // Emitted to inform that the staker identified by `blsPubKey`
    // has updated its data that can be refetched using `getStakerData()`
    event StakerUpdated(bytes blsPubKey);

    // Emitted to inform that a stakers position in the list of stakers (committee.stakerKeys) has changed
    event StakerMoved(
        bytes blsPubKey,
        uint256 newPosition,
        uint256 atFutureBlock
    );

    uint64 public constant VERSION = 8;

    /// @custom:storage-location erc7201:zilliqa.storage.DepositStorage
    struct DepositStorage {
        // The committee in the current epoch and the 2 epochs following it. The value for the current epoch
        // is stored at index (currentEpoch() % 3).
        Committee[3] _committee;
        // All stakers. Keys into this map are stored by the `Committee`.
        mapping(bytes => Staker) _stakersMap;
        // Mapping from `controlAddress` to `blsPubKey` for each staker.
        // This is legacy do not use. In upgraded contracts there may be some items still in the mapping.
        mapping(address => bytes) _stakerKeys;
        // The latest epoch for which the committee was calculated. It is implied that no changes have (yet) occurred in
        // future epochs, either because those epochs haven't happened yet or because they have happened, but no deposits
        // or withdrawals were made.
        uint64 latestComputedEpoch;
        uint256 minimumStake;
        uint256 maximumStakers;
        uint64 blocksPerEpoch;
        // Unbonding period for withdrawals measured in number of blocks (note that we have 1 second block times)
        uint256 withdrawalPeriod;
    }

    modifier onlyControlAddress(bytes calldata blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }
        if ($._stakersMap[blsPubKey].controlAddress != msg.sender) {
            revert Unauthorised();
        }
        _;
    }

    // keccak256(abi.encode(uint256(keccak256("zilliqa.storage.DepositStorage")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant DEPOSIT_STORAGE_LOCATION =
        0x958a6cf6390bd7165e3519675caa670ab90f0161508a9ee714d3db7edc507400;

    function _getDepositStorage()
        private
        pure
        returns (DepositStorage storage $)
    {
        assembly {
            $.slot := DEPOSIT_STORAGE_LOCATION
        }
    }

    function version() public view returns (uint64) {
        return _getInitializedVersion();
    }

    function _authorizeUpgrade(
        // solhint-disable-next-line no-unused-vars
        address newImplementation
    ) internal virtual override {
        require(
            msg.sender == address(0),
            "system contract must be upgraded by the system"
        );
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Do not change the order of the reinitializers!

    // explicitly set version number in contract code
    // solhint-disable-next-line no-empty-blocks
    function reinitialize() public reinitializer(VERSION) {}

    // explicitly set version number in contract code
    // solhint-disable-next-line no-empty-blocks
    function reinitialize(
        uint256 _withdrawalPeriod
    ) public reinitializer(VERSION) {
        DepositStorage storage $ = _getDepositStorage();
        $.withdrawalPeriod = _withdrawalPeriod;
    }

    function currentEpoch() public view returns (uint64) {
        DepositStorage storage $ = _getDepositStorage();
        return uint64(block.number / $.blocksPerEpoch);
    }

    function committee() private view returns (Committee storage) {
        DepositStorage storage $ = _getDepositStorage();
        if ($.latestComputedEpoch <= currentEpoch()) {
            // If the current epoch is after the latest computed epoch, it is implied that no changes have happened to
            // the committee since the latest computed epoch. Therefore, it suffices to return the committee at that
            // latest computed epoch.
            return $._committee[$.latestComputedEpoch % 3];
        } else {
            // Otherwise, the committee has been changed. The caller who made the change will have pre-computed the
            // result for us, so we can just return it.
            return $._committee[currentEpoch() % 3];
        }
    }

    function minimumStake() public view returns (uint256) {
        DepositStorage storage $ = _getDepositStorage();
        return $.minimumStake;
    }

    function maximumStakers() public view returns (uint256) {
        DepositStorage storage $ = _getDepositStorage();
        return $.maximumStakers;
    }

    function blocksPerEpoch() public view returns (uint64) {
        DepositStorage storage $ = _getDepositStorage();
        return $.blocksPerEpoch;
    }

    function leaderFromRandomness(
        uint256 randomness
    ) private view returns (bytes memory, uint256) {
        Committee storage currentCommittee = committee();
        // Get a random number in the inclusive range of 0 to (totalStake - 1)
        uint256 position = randomness % currentCommittee.totalStake;
        uint256 cummulativeStake = 0;

        for (uint256 i = 0; i < currentCommittee.stakerKeys.length; i++) {
            bytes memory stakerKey = currentCommittee.stakerKeys[i];
            uint256 stakedBalance = currentCommittee.stakers[stakerKey].balance;

            cummulativeStake += stakedBalance;

            if (position < cummulativeStake) {
                return (stakerKey, i);
            }
        }

        revert("Unable to select next leader");
    }

    function leaderAtView(
        uint256 viewNumber
    ) public view returns (bytes memory stakerKey) {
        uint256 randomness = viewNumber;
        uint256 bitmap;
        uint256 number = committee().stakerKeys.length;
        // representing stakers in a bitmap is very efficient
        // as long as their number does not exceed 255
        require(number < 256, "Too many validators");
        uint256 index;
        bytes memory output;
        do {
            randomness = uint256(keccak256(bytes.concat(bytes32(randomness))));
            (stakerKey, index) = leaderFromRandomness(randomness);
            // skip the precompile if this stakerKey has already been checked
            if (bitmap & (1 << index) != 0) continue;
            // return the stakerKey if it is the only one left even if jailed
            if (number == 1) break;
            number--;
            bitmap |= 1 << index;
            bytes memory input = abi.encodeWithSelector(
                hex"5db5c142", // bytes4(keccak256("jailed(bytes,uint256)"))
                stakerKey,
                viewNumber
            );
            uint256 inputLength = input.length;
            output = new bytes(32);
            bool success;
            assembly {
                success := staticcall(
                    gas(),
                    0x5a494c82, // "ZIL\x82"
                    add(input, 0x20),
                    inputLength,
                    add(output, 0x20),
                    32
                )
            }
            require(success, "Penalty precompile failed");
        } while (abi.decode(output, (bool)));
    }

    function leaderAtViewWithRandao(
        uint256 viewNumber
    ) public view returns (bytes memory stakerKey) {
        uint256 randomness = block.prevrandao;
        uint256 bitmap;
        uint256 number = committee().stakerKeys.length;
        // representing stakers in a bitmap is very efficient
        // as long as their number does not exceed 255
        require(number < 256, "Too many validators");
        uint256 index;
        bytes memory output;
        do {
            randomness = uint256(keccak256(bytes.concat(bytes32(randomness), bytes32(viewNumber))));
            (stakerKey, index) = leaderFromRandomness(randomness);
            // skip the precompile if this stakerKey has already been checked
            if (bitmap & (1 << index) != 0) continue;
            // return the stakerKey if it is the only one left even if jailed
            if (number == 1) break;
            number--;
            bitmap |= 1 << index;
            bytes memory input = abi.encodeWithSelector(
                hex"5db5c142", // bytes4(keccak256("jailed(bytes,uint256)"))
                stakerKey,
                viewNumber
            );
            uint256 inputLength = input.length;
            output = new bytes(32);
            bool success;
            assembly {
                success := staticcall(
                    gas(),
                    0x5a494c82, // "ZIL\x82"
                    add(input, 0x20),
                    inputLength,
                    add(output, 0x20),
                    32
                )
            }
            require(success, "Penalty precompile failed");
        } while (abi.decode(output, (bool)));
    }

    function getStakers() public view returns (bytes[] memory) {
        return committee().stakerKeys;
    }

    function getTotalStake() public view returns (uint256) {
        return committee().totalStake;
    }

    function getFutureTotalStake() public view returns (uint256) {
        DepositStorage storage $ = _getDepositStorage();
        // if `latestComputedEpoch > currentEpoch()`
        // then `latestComputedEpoch` determines the future committee we need
        // otherwise there are no committee changes after `currentEpoch()`
        // i.e. `latestComputedEpoch` determines the most recent committee
        return $._committee[$.latestComputedEpoch % 3].totalStake;
    }

    struct StakerData {
        address controlAddress;
        address rewardAddress;
        bytes peerId;
        Withdrawal[] withdrawals;
        address signingAddress;
    }

    function getStakersData()
        public
        view
        returns (
            bytes[] memory stakerKeys,
            uint256[] memory indices,
            uint256[] memory balances,
            StakerData[] memory stakers
        )
    {
        DepositStorage storage $ = _getDepositStorage();
        Committee storage currentCommittee = committee();

        stakerKeys = currentCommittee.stakerKeys;
        indices = new uint256[](stakerKeys.length);
        balances = new uint256[](stakerKeys.length);
        stakers = new StakerData[](stakerKeys.length);
        for (uint256 i = 0; i < stakerKeys.length; i++) {
            bytes memory key = stakerKeys[i];
            // The stakerKeys are not sorted by the stakers'
            // index in the current committee, therefore we
            // return the indices too, to help identify the
            // stakers in the bit vectors stored along with
            // BLS aggregate signatures
            indices[i] = currentCommittee.stakers[key].index;
            balances[i] = currentCommittee.stakers[key].balance;
            StakerData memory stakerData;
            stakerData.controlAddress = $._stakersMap[key].controlAddress;
            stakerData.rewardAddress = $._stakersMap[key].rewardAddress;
            stakerData.peerId = $._stakersMap[key].peerId;
            stakerData.signingAddress = $._stakersMap[key].signingAddress;
            stakerData.withdrawals = new Withdrawal[](
                $._stakersMap[key].withdrawals.length()
            );
            for (
                uint256 j = 0;
                j < $._stakersMap[key].withdrawals.length();
                j++
            ) {
                stakerData.withdrawals[j] = $._stakersMap[key].withdrawals.get(
                    j
                );
            }
            stakers[i] = stakerData;
        }
    }

    function getStakerData(
        bytes calldata blsPubKey
    )
        public
        view
        returns (uint256 index, uint256 balance, StakerData memory stakerData)
    {
        DepositStorage storage $ = _getDepositStorage();
        Committee storage currentCommittee = committee();
        index = currentCommittee.stakers[blsPubKey].index;
        balance = currentCommittee.stakers[blsPubKey].balance;
        stakerData.controlAddress = $._stakersMap[blsPubKey].controlAddress;
        stakerData.rewardAddress = $._stakersMap[blsPubKey].rewardAddress;
        stakerData.peerId = $._stakersMap[blsPubKey].peerId;
        stakerData.signingAddress = $._stakersMap[blsPubKey].signingAddress;
        stakerData.withdrawals = new Withdrawal[](
            $._stakersMap[blsPubKey].withdrawals.length()
        );
        for (
            uint256 j = 0;
            j < $._stakersMap[blsPubKey].withdrawals.length();
            j++
        ) {
            stakerData.withdrawals[j] = $
                ._stakersMap[blsPubKey]
                .withdrawals
                .get(j);
        }
    }

    function getStake(bytes calldata blsPubKey) public view returns (uint256) {
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }

        // We don't need to check if `blsPubKey` is in `stakerKeys` here. If the `blsPubKey` is not a staker, the
        // balance will default to zero.
        return committee().stakers[blsPubKey].balance;
    }

    function getFutureStake(
        bytes calldata blsPubKey
    ) public view returns (uint256) {
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }
        DepositStorage storage $ = _getDepositStorage();

        // if `latestComputedEpoch > currentEpoch()`
        // then `latestComputedEpoch` determines the future committee we need
        // otherwise there are no committee changes after `currentEpoch()`
        // i.e. `latestComputedEpoch` determines the most recent committee
        Committee storage latestCommittee = $._committee[
            $.latestComputedEpoch % 3
        ];

        // We don't need to check if `blsPubKey` is in `stakerKeys` here. If the `blsPubKey` is not a staker, the
        // balance will default to zero.
        return latestCommittee.stakers[blsPubKey].balance;
    }

    function getRewardAddress(
        bytes calldata blsPubKey
    ) public view returns (address) {
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }
        DepositStorage storage $ = _getDepositStorage();
        if ($._stakersMap[blsPubKey].controlAddress == address(0)) {
            revert KeyNotStaked();
        }
        return $._stakersMap[blsPubKey].rewardAddress;
    }

    function getSigningAddress(
        bytes calldata blsPubKey
    ) public view returns (address) {
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }
        DepositStorage storage $ = _getDepositStorage();
        if ($._stakersMap[blsPubKey].controlAddress == address(0)) {
            revert KeyNotStaked();
        }
        address signingAddress = $._stakersMap[blsPubKey].signingAddress;
        // If the staker was an InitialStaker on contract initialisation and have not called setSigningAddress() then there will be no signingAddress.
        // Default to controlAddress to avoid revert
        if (signingAddress == address(0)) {
            signingAddress = $._stakersMap[blsPubKey].controlAddress;
        }
        return signingAddress;
    }

    function getControlAddress(
        bytes calldata blsPubKey
    ) public view returns (address) {
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }
        DepositStorage storage $ = _getDepositStorage();
        if ($._stakersMap[blsPubKey].controlAddress == address(0)) {
            revert KeyNotStaked();
        }
        return $._stakersMap[blsPubKey].controlAddress;
    }

    function setRewardAddress(
        bytes calldata blsPubKey,
        address rewardAddress
    ) public onlyControlAddress(blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();
        $._stakersMap[blsPubKey].rewardAddress = rewardAddress;
        emit StakerUpdated(blsPubKey);
    }

    function setSigningAddress(
        bytes calldata blsPubKey,
        address signingAddress
    ) public onlyControlAddress(blsPubKey) {
        require(
            signingAddress != address(0),
            "signingAddress cannot be set to zero address"
        );
        DepositStorage storage $ = _getDepositStorage();
        $._stakersMap[blsPubKey].signingAddress = signingAddress;
        emit StakerUpdated(blsPubKey);
    }

    function setControlAddress(
        bytes calldata blsPubKey,
        address controlAddress
    ) public onlyControlAddress(blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();
        $._stakersMap[blsPubKey].controlAddress = controlAddress;
        emit StakerUpdated(blsPubKey);
    }

    function getPeerId(
        bytes calldata blsPubKey
    ) public view returns (bytes memory) {
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }
        DepositStorage storage $ = _getDepositStorage();
        if ($._stakersMap[blsPubKey].controlAddress == address(0)) {
            revert KeyNotStaked();
        }
        return $._stakersMap[blsPubKey].peerId;
    }

    function updateLatestComputedEpoch() internal {
        DepositStorage storage $ = _getDepositStorage();
        // If the latest computed epoch is less than two epochs ahead of the current one, we must fill in the missing
        // epochs. This just involves copying the committee from the previous epoch to the next one. It is assumed that
        // the caller will then want to update the future epochs.
        if ($.latestComputedEpoch < currentEpoch() + 2) {
            Committee storage latestComputedCommittee = $._committee[
                $.latestComputedEpoch % 3
            ];
            // Note the early exit condition if `latestComputedEpoch + 3` which ensures this loop will not run more
            // than twice. This is acceptable because we only store 3 committees at a time, so once we have updated two
            // of them to the latest computed committee, there is no more work to do.
            for (
                uint64 i = $.latestComputedEpoch + 1;
                i <= currentEpoch() + 2 && i < $.latestComputedEpoch + 3;
                i++
            ) {
                // The operation we want to do is: `_committee[i % 3] = latestComputedCommittee` but we need to do it
                // explicitly because `stakers` is a mapping.

                // Delete old keys from `_committee[i % 3].stakers`.
                for (
                    uint256 j = 0;
                    j < $._committee[i % 3].stakerKeys.length;
                    j++
                ) {
                    delete $._committee[i % 3].stakers[
                        $._committee[i % 3].stakerKeys[j]
                    ];
                }

                $._committee[i % 3].totalStake = latestComputedCommittee
                    .totalStake;
                $._committee[i % 3].stakerKeys = latestComputedCommittee
                    .stakerKeys;
                for (
                    uint256 j = 0;
                    j < latestComputedCommittee.stakerKeys.length;
                    j++
                ) {
                    bytes storage stakerKey = latestComputedCommittee
                        .stakerKeys[j];
                    $._committee[i % 3].stakers[
                        stakerKey
                    ] = latestComputedCommittee.stakers[stakerKey];
                }
            }

            $.latestComputedEpoch = currentEpoch() + 2;
        }
    }

    // Returns the next block number at which new stakers are added,
    // existing ones removed and/or deposits of existing stakers change
    function nextUpdate() public view returns (uint256 blockNumber) {
        DepositStorage storage $ = _getDepositStorage();
        if ($.latestComputedEpoch > currentEpoch())
            blockNumber = $.latestComputedEpoch * $.blocksPerEpoch;
    }

    // keep in-sync with zilliqa/src/precompiles.rs
    function _blsVerify(
        bytes memory message,
        bytes memory pubkey,
        bytes memory signature
    ) internal view returns (bool) {
        bytes memory input = abi.encodeWithSelector(
            hex"a65ebb25", // bytes4(keccak256("blsVerify(bytes,bytes,bytes)"))
            message,
            signature,
            pubkey
        );
        uint256 inputLength = input.length;
        bytes memory output = new bytes(32);
        bool success;
        assembly {
            success := staticcall(
                gas(),
                0x5a494c81, // "ZIL\x81"
                add(input, 0x20),
                inputLength,
                add(output, 0x20),
                32
            )
        }
        require(success, "blsVerify");
        bool result = abi.decode(output, (bool));
        return result;
    }

    function deposit(
        bytes calldata blsPubKey,
        bytes calldata peerId,
        bytes calldata signature,
        address rewardAddress,
        address signingAddress
    ) public payable {
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }
        if (peerId.length != 38) {
            revert UnexpectedArgumentLength("peer id", 38);
        }
        if (signature.length != 96) {
            revert UnexpectedArgumentLength("signature", 96);
        }
        DepositStorage storage $ = _getDepositStorage();

        bytes memory message = abi.encodePacked(
            blsPubKey,
            uint64(block.chainid),
            msg.sender
        );

        // Verify bls signature
        if (!_blsVerify(message, blsPubKey, signature)) {
            revert RogueKeyCheckFailed();
        }

        if (msg.value < $.minimumStake) {
            revert StakeAmountTooLow();
        }

        Staker storage staker = $._stakersMap[blsPubKey];
        staker.peerId = peerId;
        staker.rewardAddress = rewardAddress;
        staker.signingAddress = signingAddress;
        staker.controlAddress = msg.sender;

        updateLatestComputedEpoch();

        Committee storage futureCommittee = $._committee[
            (currentEpoch() + 2) % 3
        ];

        if (futureCommittee.stakerKeys.length >= $.maximumStakers) {
            revert TooManyStakers();
        }
        if (futureCommittee.stakers[blsPubKey].index != 0) {
            revert KeyAlreadyStaked();
        }

        futureCommittee.totalStake += msg.value;
        futureCommittee.stakers[blsPubKey].balance = msg.value;
        futureCommittee.stakers[blsPubKey].index =
            futureCommittee.stakerKeys.length + 1;
        futureCommittee.stakerKeys.push(blsPubKey);

        emit StakerAdded(blsPubKey, nextUpdate(), msg.value);
    }

    function depositTopup(
        bytes calldata blsPubKey
    ) public payable onlyControlAddress(blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();

        updateLatestComputedEpoch();

        Committee storage futureCommittee = $._committee[
            (currentEpoch() + 2) % 3
        ];
        if (futureCommittee.stakers[blsPubKey].index == 0) {
            revert KeyNotStaked();
        }

        futureCommittee.totalStake += msg.value;
        futureCommittee.stakers[blsPubKey].balance += msg.value;

        emit StakeChanged(
            blsPubKey,
            nextUpdate(),
            futureCommittee.stakers[blsPubKey].balance
        );
    }

    function unstake(
        bytes calldata blsPubKey,
        uint256 amount
    ) public onlyControlAddress(blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();

        updateLatestComputedEpoch();

        Committee storage futureCommittee = $._committee[
            (currentEpoch() + 2) % 3
        ];
        if (futureCommittee.stakers[blsPubKey].index == 0) {
            revert KeyNotStaked();
        }

        uint256 currentBalance = futureCommittee.stakers[blsPubKey].balance;
        require(
            currentBalance >= amount,
            "amount is greater than staked balance"
        );

        if (currentBalance - amount == 0) {
            require(futureCommittee.stakerKeys.length > 1, "too few stakers");

            // Remove the staker from the future committee, because their staked amount has gone to zero.
            futureCommittee.totalStake -= amount;

            uint256 deleteIndex = futureCommittee.stakers[blsPubKey].index - 1;
            uint256 lastIndex = futureCommittee.stakerKeys.length - 1;

            if (deleteIndex != lastIndex) {
                // Move the last staker in `stakerKeys` to the position of the staker we want to delete.
                bytes storage lastStakerKey = futureCommittee.stakerKeys[
                    lastIndex
                ];
                futureCommittee.stakerKeys[deleteIndex] = lastStakerKey;
                // We need to remember to update the moved staker's `index` too.
                futureCommittee.stakers[lastStakerKey].index = futureCommittee
                    .stakers[blsPubKey]
                    .index;
                emit StakerMoved(lastStakerKey, deleteIndex, nextUpdate());
            }

            // It is now safe to delete the final staker in the list.
            futureCommittee.stakerKeys.pop();
            delete futureCommittee.stakers[blsPubKey];

            // Note that we leave the staker in `_stakersMap` forever.

            emit StakerRemoved(blsPubKey, nextUpdate());
        } else {
            require(
                currentBalance - amount >= $.minimumStake,
                "unstaking this amount would take the validator below the minimum stake"
            );

            // Partial unstake. The staker stays in the committee, but with a reduced stake.
            futureCommittee.totalStake -= amount;
            futureCommittee.stakers[blsPubKey].balance -= amount;

            emit StakeChanged(
                blsPubKey,
                nextUpdate(),
                futureCommittee.stakers[blsPubKey].balance
            );
        }

        // Enqueue the withdrawal for this staker.
        Deque.Withdrawals storage withdrawals = $
            ._stakersMap[blsPubKey]
            .withdrawals;
        Withdrawal storage currentWithdrawal;
        // We know `withdrawals` is sorted by `startedAt`. We also know `block.number` is monotonically
        // non-decreasing. Therefore if there is an existing entry with a `startedAt = block.number`, it must be
        // at the end of the queue.
        if (
            withdrawals.length() != 0 &&
            withdrawals.back().startedAt == block.number
        ) {
            // They have already made a withdrawal at this time, so grab a reference to the existing one.
            currentWithdrawal = withdrawals.back();
        } else {
            // Add a new withdrawal to the end of the queue.
            currentWithdrawal = withdrawals.pushBack();
            currentWithdrawal.startedAt = block.number;
            currentWithdrawal.amount = 0;
        }
        currentWithdrawal.amount += amount;
    }

    function withdraw(bytes calldata blsPubKey) public {
        _withdraw(blsPubKey, 0);
    }

    function withdraw(bytes calldata blsPubKey, uint256 count) public {
        _withdraw(blsPubKey, count);
    }

    function withdrawalPeriod() public view returns (uint256) {
        DepositStorage storage $ = _getDepositStorage();
        return $.withdrawalPeriod;
    }

    function _withdraw(
        bytes calldata blsPubKey,
        uint256 count
    ) internal onlyControlAddress(blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();

        uint256 releasedAmount = 0;

        Deque.Withdrawals storage withdrawals = $
            ._stakersMap[blsPubKey]
            .withdrawals;
        count = (count == 0 || count > withdrawals.length())
            ? withdrawals.length()
            : count;

        while (count > 0) {
            Withdrawal storage withdrawal = withdrawals.front();
            if (withdrawal.startedAt + withdrawalPeriod() <= block.number) {
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
