// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {Deque, Withdrawal} from "./utils/deque.sol";

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
    // Currently active balance
    // Invariant: `balance >= minimumStake`
    uint256 balance;
}

struct Committee {
    // Invariant: Equal to the sum of `balances` in `stakers`.
    uint256 totalStake;
    bytes[] stakerKeys;
}

struct BalanceUpdate {
    int256 amount;
    // The epoch in which this balance update becomes active
    uint256 epoch;
}

struct Balance {
    uint256 active;
    BalanceUpdate[] pending;
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
    // Balance including pending updates in upcoming epochs
    Balance balance;
    // The index of the value in the `stakers` array plus 1.
    // Index 0 is used to mean a value is not present.
    uint256 index;
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
    event StakerMoved(bytes blsPubKey, uint256 newPosition, uint256 atFutureBlock);

    uint64 public constant VERSION = 3;

    /// @custom:storage-location erc7201:zilliqa.storage.DepositStorage
    struct DepositStorage {
        // The committee in the current epoch and the 2 epochs following it. The value for the current epoch
        // is stored at index (currentEpoch() % 3).
        Committee[3] _committee;
        // All stakers. Keys into this map are stored by the `Committee`.
        mapping(bytes => Staker) _stakersMap;
        // Keys of items in _stakersMap
        bytes[] _stakersKeys;
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

    // explicitly set version number in contract code
    // solhint-disable-next-line no-empty-blocks
    function reinitialize() public reinitializer(VERSION) {}

    function currentEpoch() public view returns (uint64) {
        DepositStorage storage $ = _getDepositStorage();
        return uint64(block.number / $.blocksPerEpoch);
    }

    function committee(bool includeAll) private view returns (Committee memory) {    
        DepositStorage storage $ = _getDepositStorage();
        Committee memory currentCommittee;
        uint256 currentEpochVal = currentEpoch();
        uint8 numAdditions = 0;

        for (
            uint256 i = 0;
            i < $._stakersKeys.length;
            i++
        ) { 
            bytes memory stakerKey = $._stakersKeys[i];
            uint256 balance = getStakersBalance(stakerKey, includeAll);
            // If staker has active balance then add them to the committee 
            if (balance > 0) {
                numAdditions += 1;
                currentCommittee.totalStake += uint256(balance);
            }
        }

        currentCommittee.stakerKeys = new bytes[](numAdditions);
        uint8 numAdded = 0;
        for (
            uint256 i = 0;
            i < $._stakersKeys.length;
            i++
        ) { 
            bytes memory stakerKey = $._stakersKeys[i];
            uint256 balance = getStakersBalance(stakerKey, includeAll);
            // If staker has active balance then add them to the committee 
            if (balance > 0) {
                currentCommittee.stakerKeys[numAdded] = stakerKey;
                numAdded += 1;
            }
        }

        return  currentCommittee;
    }

    function getStakersBalance(bytes memory stakerKey, bool includeAll) private view returns (uint256) {
        DepositStorage storage $ = _getDepositStorage();
        uint256 currentEpochVal = currentEpoch();

        Staker memory staker = $._stakersMap[stakerKey];
        if (staker.controlAddress == address(0)) {
            return uint256(0);
        }

        uint256 balance = staker.balance.active;

        // Add any pending balance updates which may now be considered active
        for (
            uint256 i = 0;
            i < staker.balance.pending.length;
            i++
        ) {
            // Include all balance updates or only those currenlty active
            if (includeAll || staker.balance.pending[i].epoch <= currentEpochVal) {
                if (staker.balance.pending[i].amount > 0) {
                    balance += uint256(staker.balance.pending[i].amount);
                } else {
                    // we ensure balance never goes below 0 in unstake() 
                    balance -= uint256(-staker.balance.pending[i].amount);
                }
            }
        }
        return balance;
    }

    function foldStakersBalance(bytes memory stakerKey) private {
        DepositStorage storage $ = _getDepositStorage();
        uint256 currentEpochVal = currentEpoch();

        Staker memory staker = $._stakersMap[stakerKey];
        uint256 balance = staker.balance.active;
        uint256 removePendingBalancesUptoIndex;
        // Add any pending balance updates which may now be considered active
        for (
            uint256 i = 0;
            i < staker.balance.pending.length;
            i++
        ) {
            // Include all balance updates or only those currently active
            if (staker.balance.pending[i].epoch <= currentEpochVal) {
                if (staker.balance.pending[i].amount > 0) {
                    balance += uint256(staker.balance.pending[i].amount);
                } else {
                    // we ensure balance never goes below 0 in unstake() 
                    balance -= uint256(-staker.balance.pending[i].amount);
                }
                removePendingBalancesUptoIndex = i + 1;
            }
        }
        // Pending balance array is in order of epochs. Ie all items in epoch x will be before items in epoch x+1
        // Therefore to remove items we can take a slice of the array and copy the result back into storage
        if (removePendingBalancesUptoIndex > 0) {
            BalanceUpdate[] memory slice = new BalanceUpdate[](staker.balance.pending.length - removePendingBalancesUptoIndex);
            for (uint256 i = removePendingBalancesUptoIndex; i < staker.balance.pending.length; i++) {
                slice[i - removePendingBalancesUptoIndex] = staker.balance.pending[i];
            }

            // Write pending values to balance if they are now active
            staker.balance.active = balance;
            staker.balance.pending = slice;
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
        DepositStorage storage $ = _getDepositStorage();
        Committee memory currentCommittee = committee(false);
        // Get a random number in the inclusive range of 0 to (totalStake - 1)
        uint256 position = randomness % currentCommittee.totalStake;
        uint256 cummulativeStake = 0;

        // TODO: Consider binary search for performance. Or consider an alias method for O(1) performance.
        for (uint256 i = 0; i < currentCommittee.stakerKeys.length; i++) {
            bytes memory stakerKey = currentCommittee.stakerKeys[i];
            uint256 stakedBalance = getStakersBalance(stakerKey, false);

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
        return committee(false).stakerKeys;
    }

    function getTotalStake() public view returns (uint256) {
        return committee(false).totalStake;
    }

    function getFutureTotalStake() public view returns (uint256) {
        return committee(true).totalStake;
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
        // TODO clean up double call to _getDepositStorage() here
        DepositStorage storage $ = _getDepositStorage();
        Committee memory currentCommittee = committee(false);

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
            indices[i] = i + 1;
            balances[i] = getStakersBalance(key, false);
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
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }
        DepositStorage storage $ = _getDepositStorage();
        Committee memory currentCommittee = committee(false);

        for (uint256 i = 0; i < currentCommittee.stakerKeys.length; i++) {           
            if (compareBytes(blsPubKey, currentCommittee.stakerKeys[i])) {
                index = i;
            }  
        }
        balance = getStakersBalance(blsPubKey, false);
        staker = $._stakersMap[blsPubKey];
    }

    function compareBytes(bytes memory bytes_1, bytes memory bytes_2) private view returns (bool) {
        if (bytes_1.length != bytes_2.length) {
            return false;
        }
        for (uint i = 0; i < bytes_1.length; i++) {
            if (bytes_1[i] != bytes_2[i]) {
                return false;
            }
        }
        return true;
    }

    function getStake(bytes calldata blsPubKey) public view returns (uint256) {
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }

        // We don't need to check if `blsPubKey` is in `stakerKeys` here. If the `blsPubKey` is not a staker, the
        // balance will default to zero.
        return getStakersBalance(blsPubKey, false);
    }

    function getFutureStake(
        bytes calldata blsPubKey
    ) public view returns (uint256) {
        if (blsPubKey.length != 48) {
            revert UnexpectedArgumentLength("bls public key", 48);
        }

        // We don't need to check if `blsPubKey` is in `stakerKeys` here. If the `blsPubKey` is not a staker, the
        // balance will default to zero.
        return getStakersBalance(blsPubKey, true);
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

        if (getStakersBalance(blsPubKey, true) != 0) {
            revert KeyAlreadyStaked();
        }

        Staker storage staker = $._stakersMap[blsPubKey];
        staker.peerId = peerId;
        staker.rewardAddress = rewardAddress;
        staker.signingAddress = signingAddress;
        staker.controlAddress = msg.sender;
        staker.balance.pending.push(BalanceUpdate({
            amount:int256(msg.value),
            epoch: currentEpoch() + 2
        }));

        Committee memory futureCommittee = committee(true);
        if (futureCommittee.stakerKeys.length >= $.maximumStakers) {
            revert TooManyStakers();
        }

        $.latestComputedEpoch = currentEpoch() + 2;
        $._stakersKeys.push(blsPubKey);

        emit StakerAdded(blsPubKey, nextUpdate(), msg.value);
    }

    function depositTopup(bytes calldata blsPubKey) public payable onlyControlAddress(blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();
        foldStakersBalance(blsPubKey);

        uint256 currentBalance = getStakersBalance(blsPubKey, true);
        if (currentBalance == 0) {
            revert KeyNotStaked();
        }

        Staker storage staker = $._stakersMap[blsPubKey];
        staker.balance.pending.push(BalanceUpdate({
            amount:int256(msg.value),
            epoch: currentEpoch() + 2
        }));
        $.latestComputedEpoch = currentEpoch() + 2;

        emit StakeChanged(
            blsPubKey,
            nextUpdate(),
            currentBalance + msg.value
        );
    }

    function unstake(bytes calldata blsPubKey, uint256 amount) public onlyControlAddress(blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();
        foldStakersBalance(blsPubKey);

        Staker storage staker = $._stakersMap[blsPubKey];
        uint256 currentBalance = getStakersBalance(blsPubKey, true);

        if (currentBalance == 0) {
            revert KeyNotStaked();
        }

        require(
            currentBalance >= amount,
            "amount is greater than staked balance"
        );

        staker.balance.pending.push(BalanceUpdate({
            amount: -int256(amount),
            epoch: currentEpoch() + 2
        }));
        $.latestComputedEpoch = currentEpoch() + 2;

        Committee memory futureCommittee = committee(true);

        if (currentBalance - amount == 0) {
            require(futureCommittee.stakerKeys.length > 1, "too few stakers");

            // // Remove the staker from the future committee, because their staked amount has gone to zero.
            // futureCommittee.totalStake -= amount;

            // uint256 deleteIndex = futureCommittee.stakers[blsPubKey].index - 1;
            // uint256 lastIndex = futureCommittee.stakerKeys.length - 1;

            // if (deleteIndex != lastIndex) {
            //     // Move the last staker in `stakerKeys` to the position of the staker we want to delete.
            //     bytes storage lastStakerKey = futureCommittee.stakerKeys[
            //         lastIndex
            //     ];
            //     futureCommittee.stakerKeys[deleteIndex] = lastStakerKey;
            //     // We need to remember to update the moved staker's `index` too.
            //     futureCommittee.stakers[lastStakerKey].index = futureCommittee
            //         .stakers[blsPubKey]
            //         .index;  
            // TODO deal with this. Indices different now
            //     emit StakerMoved(lastStakerKey, deleteIndex, nextUpdate());
            // }

            // // It is now safe to delete the final staker in the list.
            // futureCommittee.stakerKeys.pop();
            // delete futureCommittee.stakers[blsPubKey];

            // Note that we leave the staker in `_stakersMap` forever.

            emit StakerRemoved(blsPubKey, nextUpdate());
        } else {
            require(
                currentBalance - amount >= $.minimumStake,
                "unstaking this amount would take the validator below the minimum stake"
            );

            // // Partial unstake. The staker stays in the committee, but with a reduced stake.
            // futureCommittee.totalStake -= amount;
            // futureCommittee.stakers[blsPubKey].balance -= amount;

            emit StakeChanged(
                blsPubKey,
                nextUpdate(),
                currentBalance - amount
            );
        }
        

        // Enqueue the withdrawal for this staker.
        Deque.Withdrawals storage withdrawals = $._stakersMap[blsPubKey].withdrawals;
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

    /// Unbonding period for withdrawals measured in number of blocks (note that we have 1 second block times)
    function withdrawalPeriod() public view returns (uint256) {
        // shorter unbonding period for testing deposit withdrawals
        if (block.chainid == 33469) return 5 minutes;
        return 2 weeks;
    }

    function _withdraw(bytes calldata blsPubKey, uint256 count) internal onlyControlAddress(blsPubKey) {
        DepositStorage storage $ = _getDepositStorage();

        uint256 releasedAmount = 0;

        Deque.Withdrawals storage withdrawals = $._stakersMap[blsPubKey].withdrawals;
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