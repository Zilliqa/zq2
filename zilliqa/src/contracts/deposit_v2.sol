// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Deque, Withdrawal} from "./utils/deque.sol";

using Deque for Deque.Withdrawals;

/// Argument has unexpected length
/// @param argument name of argument
/// @param required expected length
error UnexpectedArgumentLength(string argument, uint256 required);

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
}

// Parameters passed to the deposit contract constructor, for each staker who should be in the initial committee.
struct InitialStaker {
    bytes blsPubKey;
    bytes peerId;
    address rewardAddress;
    address controlAddress;
    uint256 amount;
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

    uint64 public constant VERSION = 2;

    /// @custom:storage-location erc7201:zilliqa.storage.DepositStorage
    struct DepositStorage {
        // The committee in the current epoch and the 2 epochs following it. The value for the current epoch
        // is stored at index (currentEpoch() % 3).
        Committee[3] _committee;
        // All stakers. Keys into this map are stored by the `Committee`.
        mapping(bytes => Staker) _stakersMap;
        // Mapping from `controlAddress` to `blsPubKey` for each staker.
        mapping(address => bytes) _stakerKeys;
        // The latest epoch for which the committee was calculated. It is implied that no changes have (yet) occurred in
        // future epochs, either because those epochs haven't happened yet or because they have happened, but no deposits
        // or withdrawals were made.
        uint64 latestComputedEpoch;
        uint256 minimumStake;
        uint256 maximumStakers;
        uint64 blocksPerEpoch;
    }

    modifier onlyControlAddress(bytes calldata blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }
        require(
            $._stakersMap[blsPubKey].controlAddress == msg.sender,
            "sender is not the control address"
        );
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

    // explicitly set version number in contract code
    // solhint-disable-next-line no-empty-blocks
    function reinitialize() public reinitializer(VERSION) {}

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
    ) private view returns (bytes memory) {
        Committee storage currentCommittee = committee();
        // Get a random number in the inclusive range of 0 to (totalStake - 1)
        uint256 position = randomness % currentCommittee.totalStake;
        uint256 cummulativeStake = 0;

        // TODO: Consider binary search for performance. Or consider an alias method for O(1) performance.
        for (uint256 i = 0; i < currentCommittee.stakerKeys.length; i++) {
            bytes memory stakerKey = currentCommittee.stakerKeys[i];
            uint256 stakedBalance = currentCommittee.stakers[stakerKey].balance;

            cummulativeStake += stakedBalance;

            if (position < cummulativeStake) {
                return stakerKey;
            }
        }

        revert("Unable to select next leader");
    }

    function leaderAtView(
        uint256 viewNumber
    ) public view returns (bytes memory) {
        uint256 randomness = uint256(
            keccak256(bytes.concat(bytes32(viewNumber)))
        );
        return leaderFromRandomness(randomness);
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

    function getStakersData()
        public
        view
        returns (
            bytes[] memory stakerKeys,
            uint256[] memory indices,
            uint256[] memory balances,
            Staker[] memory stakers
        )
    {
        // TODO clean up doule call to _getDepositStorage() here
        DepositStorage storage $ = _getDepositStorage();
        Committee storage currentCommittee = committee();

        stakerKeys = currentCommittee.stakerKeys;
        balances = new uint256[](stakerKeys.length);
        stakers = new Staker[](stakerKeys.length);
        for (uint256 i = 0; i < stakerKeys.length; i++) {
            bytes memory key = stakerKeys[i];
            // The stakerKeys are not sorted by the stakers'
            // index in the current committee, therefore we
            // return the indices too, to help identify the
            // stakers in the bit vectors stored along with
            // BLS aggregate signatures
            indices[i] = currentCommittee.stakers[key].index;
            balances[i] = currentCommittee.stakers[key].balance;
            stakers[i] = $._stakersMap[key];
        }
    }

    function getStakerData(
        bytes calldata blsPubKey
    )
        public
        view
        returns (uint256 index, uint256 balance, Staker memory staker)
    {
        DepositStorage storage $ = _getDepositStorage();
        Committee storage currentCommittee = committee();
        index = currentCommittee.stakers[blsPubKey].index;
        balance = currentCommittee.stakers[blsPubKey].balance;
        staker = $._stakersMap[blsPubKey];
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
    }

    function setControlAddress(
        bytes calldata blsPubKey,
        address controlAddress
    ) public onlyControlAddress(blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();
        $._stakersMap[blsPubKey].controlAddress = controlAddress;
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
    function _popVerify(
        bytes memory pubkey,
        bytes memory signature
    ) internal view returns (bool) {
        bytes memory input = abi.encodeWithSelector(
            hex"bfd24965", // bytes4(keccak256("popVerify(bytes,bytes)"))
            signature,
            pubkey
        );
        uint256 inputLength = input.length;
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

        // Verify signature as a proof-of-possession of the private key.
        bool pop = _popVerify(blsPubKey, signature);
        if (!pop) {
            revert RogueKeyCheckFailed();
        }

        Staker storage staker = $._stakersMap[blsPubKey];

        if (msg.value < $.minimumStake) {
            revert StakeAmountTooLow();
        }

        $._stakerKeys[msg.sender] = blsPubKey;
        staker.peerId = peerId;
        staker.rewardAddress = rewardAddress;
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
            futureCommittee.stakerKeys.length +
            1;
        futureCommittee.stakerKeys.push(blsPubKey);

        emit StakerAdded(blsPubKey, nextUpdate(), msg.value);
    }

    function depositTopup() public payable {
        DepositStorage storage $ = _getDepositStorage();
        bytes storage stakerKey = $._stakerKeys[msg.sender];
        if (stakerKey.length == 0) {
            revert KeyNotStaked();
        }

        updateLatestComputedEpoch();

        Committee storage futureCommittee = $._committee[
            (currentEpoch() + 2) % 3
        ];
        if (futureCommittee.stakers[stakerKey].index == 0) {
            revert KeyNotStaked();
        }
        futureCommittee.totalStake += msg.value;
        futureCommittee.stakers[stakerKey].balance += msg.value;

        emit StakeChanged(
            stakerKey,
            nextUpdate(),
            futureCommittee.stakers[stakerKey].balance
        );
    }

    function unstake(uint256 amount) public {
        DepositStorage storage $ = _getDepositStorage();
        bytes storage stakerKey = $._stakerKeys[msg.sender];
        if (stakerKey.length == 0) {
            revert KeyNotStaked();
        }
        Staker storage staker = $._stakersMap[stakerKey];

        updateLatestComputedEpoch();

        Committee storage futureCommittee = $._committee[
            (currentEpoch() + 2) % 3
        ];
        if (futureCommittee.stakers[stakerKey].index == 0) {
            revert KeyNotStaked();
        }

        require(
            futureCommittee.stakers[stakerKey].balance >= amount,
            "amount is greater than staked balance"
        );

        if (futureCommittee.stakers[stakerKey].balance - amount == 0) {
            require(futureCommittee.stakerKeys.length > 1, "too few stakers");

            // Remove the staker from the future committee, because their staked amount has gone to zero.
            futureCommittee.totalStake -= amount;

            uint256 deleteIndex = futureCommittee.stakers[stakerKey].index - 1;
            uint256 lastIndex = futureCommittee.stakerKeys.length - 1;

            if (deleteIndex != lastIndex) {
                // Move the last staker in `stakerKeys` to the position of the staker we want to delete.
                bytes storage lastStakerKey = futureCommittee.stakerKeys[
                    lastIndex
                ];
                futureCommittee.stakerKeys[deleteIndex] = lastStakerKey;
                // We need to remember to update the moved staker's `index` too.
                futureCommittee.stakers[lastStakerKey].index = futureCommittee
                    .stakers[stakerKey]
                    .index;
            }

            // It is now safe to delete the final staker in the list.
            futureCommittee.stakerKeys.pop();
            delete futureCommittee.stakers[stakerKey];

            // Note that we leave the staker in `_stakersMap` forever.

            emit StakerRemoved(stakerKey, nextUpdate());
        } else {
            require(
                futureCommittee.stakers[stakerKey].balance - amount >=
                    $.minimumStake,
                "unstaking this amount would take the validator below the minimum stake"
            );

            // Partial unstake. The staker stays in the committee, but with a reduced stake.
            futureCommittee.totalStake -= amount;
            futureCommittee.stakers[stakerKey].balance -= amount;

            emit StakeChanged(
                stakerKey,
                nextUpdate(),
                futureCommittee.stakers[stakerKey].balance
            );
        }

        // Enqueue the withdrawal for this staker.
        Deque.Withdrawals storage withdrawals = staker.withdrawals;
        Withdrawal storage currentWithdrawal;
        // We know `withdrawals` is sorted by `startedAt`. We also know `block.timestamp` is monotonically
        // non-decreasing. Therefore if there is an existing entry with a `startedAt = block.timestamp`, it must be
        // at the end of the queue.
        if (
            withdrawals.length() != 0 &&
            withdrawals.back().startedAt == block.timestamp
        ) {
            // They have already made a withdrawal at this time, so grab a reference to the existing one.
            currentWithdrawal = withdrawals.back();
        } else {
            // Add a new withdrawal to the end of the queue.
            currentWithdrawal = withdrawals.pushBack();
            currentWithdrawal.startedAt = block.timestamp;
            currentWithdrawal.amount = 0;
        }
        currentWithdrawal.amount += amount;
    }

    function withdraw() public {
        _withdraw(0);
    }

    function withdraw(uint256 count) public {
        _withdraw(count);
    }

    function withdrawalPeriod() public view returns (uint256) {
        // shorter unbonding period for testing deposit withdrawals
        if (block.chainid == 33469) return 5 minutes;
        return 2 weeks;
    }

    function _withdraw(uint256 count) internal {
        uint256 releasedAmount = 0;

        DepositStorage storage $ = _getDepositStorage();
        Staker storage staker = $._stakersMap[$._stakerKeys[msg.sender]];

        Deque.Withdrawals storage withdrawals = staker.withdrawals;
        count = (count == 0 || count > withdrawals.length())
            ? withdrawals.length()
            : count;

        while (count > 0) {
            Withdrawal storage withdrawal = withdrawals.front();
            if (withdrawal.startedAt + withdrawalPeriod() <= block.timestamp) {
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
