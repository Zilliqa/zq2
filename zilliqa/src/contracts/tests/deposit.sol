// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.26;
import {Deposit as DepositV5} from "../deposit_v5.sol";
import {Deposit as DepositV6} from "../deposit_v6.sol";
import {Deposit} from "../deposit_v7.sol";
import {Deposit as DepositV8} from "../deposit_v8.sol";
import {DepositInit, InitialStaker} from "../deposit_v1.sol";
import {
    Test,
    console2 as console
} from "@openzeppelin/lib/forge-std/src/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Testing contract for deposit_v4 development
/* solhint-disable no-console,func-name-mixedcase,explicit-types */

contract PopVerifyPrecompile {
    function popVerify(bytes memory, bytes memory) public pure returns (bool) {
        return true;
    }
}

contract BlsVerifyPrecompile {
    function blsVerify(
        bytes memory,
        bytes memory,
        bytes memory
    ) public pure returns (bool) {
        return true;
    }
}

contract DepositTest is Test {
    address payable internal proxy;
    DepositInit internal depositInitContract;
    Deposit internal depositContract;
    uint8 internal contractVersion = 7;
    uint256 internal withdrawalPeriod = uint256(36);

    bool internal printGasUsage = false;
    address[2] internal owners = [vm.addr(uint256(1)), vm.addr(uint256(2))];
    address[2] internal stakers = [
        0xd819fFcE7A58b1E835c25617Db7b46a00888B013,
        0x092E5E57955437876dA9Df998C96e2BE19341670
    ];
    bytes[2] internal blsPubKeys = [
        bytes(
            hex"92370645a6ad97d8a4e4b44b8e6db63ab8409473310ac7b21063809450192bace7fb768d60c697a18bbf98b4ddb511f1"
        ),
        bytes(
            hex"92370645a6ad97d8a4e4b44b8e6db63ab8409473310ac7b21063809450192bace7fb768d60c697a18bbf98b4ddb511f2"
        )
    ];
    bytes internal peerId =
        bytes(
            hex"002408011220bed0be7a6dfa10c2335148e04927155a726174d6bac61a09ad8e2f72ac697eda"
        );

    // bytes[] expected_stakerKeys_storage;
    // uint256[] expected_indices_storage;
    // uint256[] expected_amounts_storage;

    constructor() {
        vm.deal(address(0), 40_000_000 ether);
        vm.deal(owners[0], 40_000_000 ether);
        vm.deal(owners[1], 40_000_000 ether);

        vm.deal(stakers[0], 0);
        vm.deal(stakers[1], 0);

        vm.startPrank(address(0));

        // Deploy initial version
        address depositContractInitialAddr = address(new DepositInit());
        depositInitContract = DepositInit(depositContractInitialAddr);

        bytes memory initializerCall = abi.encodeWithSignature(
            "initialize(uint256,uint256,uint64,(bytes,bytes,address,address,uint256)[])",
            uint256(10 ether),
            uint256(256),
            uint64(10),
            new InitialStaker[](0)
        );
        proxy = payable(
            new ERC1967Proxy(depositContractInitialAddr, initializerCall)
        );
        depositInitContract = DepositInit(proxy);

        // Upgrade to deposit_v5
        address depositContractAddr = address(new DepositV5());
        bytes memory reinitializerCall = abi.encodeWithSignature(
            "reinitialize(uint256)",
            withdrawalPeriod
        );
        depositInitContract.upgradeToAndCall(
            depositContractAddr,
            reinitializerCall
        );

        // Upgrade to deposit_v6
        depositContractAddr = address(new DepositV6());
        reinitializerCall = abi.encodeWithSignature("reinitialize()");
        depositInitContract.upgradeToAndCall(
            depositContractAddr,
            reinitializerCall
        );

        // Upgrade to deposit_v7
        depositContractAddr = address(new Deposit());
        reinitializerCall = abi.encodeWithSignature(
            "reinitialize(uint256)",
            withdrawalPeriod
        );
        depositInitContract.upgradeToAndCall(
            depositContractAddr,
            reinitializerCall
        );

        // Upgrade to deposit_v8
        depositContractAddr = address(new DepositV8());
        reinitializerCall = abi.encodeWithSignature("reinitialize()");
        depositInitContract.upgradeToAndCall(
            depositContractAddr,
            reinitializerCall
        );

        depositContract = DepositV8(proxy);

        // Other setup
        vm.etch(address(0x5a494c81), address(new BlsVerifyPrecompile()).code);
        vm.stopPrank();
    }

    function test_contract_upgrade() public {
        assertEq(depositContract.version(), contractVersion);
        assertEq(depositContract.withdrawalPeriod(), withdrawalPeriod);
    }

    function test_deposit() public {
        // Deposit owner 0
        uint256 depositOwner0Amount = 20 ether;
        deposit(0, depositOwner0Amount);

        checkGetStake(blsPubKeys[0], 0);
        checkGetFutureStake(blsPubKeys[0], depositOwner0Amount);

        // Roll ahead 2 epochs
        vm.roll(block.number + depositContract.blocksPerEpoch() * 2);

        checkGetStake(blsPubKeys[0], depositOwner0Amount);
        checkGetFutureStake(blsPubKeys[0], depositOwner0Amount);

        // Deposit owner 1
        uint256 depositOwner1Amount = 10 ether;
        deposit(1, depositOwner1Amount);

        checkGetStake(blsPubKeys[1], 0);
        checkGetFutureStake(blsPubKeys[1], depositOwner1Amount);

        // Roll ahead 2 epochs
        vm.roll(block.number + depositContract.blocksPerEpoch() * 2);

        checkGetStake(blsPubKeys[1], depositOwner1Amount);
        checkGetFutureStake(blsPubKeys[1], depositOwner1Amount);
        checkGetTotalStake(depositOwner0Amount + depositOwner1Amount);
        checkGetTotalFutureStake(depositOwner0Amount + depositOwner1Amount);
    }

    function test_deposit_top_up() public {
        uint256 depositAmount = 20 ether;
        deposit(0, depositAmount);

        // Roll ahead 2 epochs
        vm.roll(block.number + depositContract.blocksPerEpoch() * 2);

        checkGetStake(blsPubKeys[0], depositAmount);

        uint256 topUpAmount = 3 ether;
        depositTopUp(0, topUpAmount);

        checkGetStake(blsPubKeys[0], depositAmount);
        checkGetFutureStake(blsPubKeys[0], depositAmount + topUpAmount);

        // Roll ahead 2 epochs
        vm.roll(block.number + depositContract.blocksPerEpoch() * 2);

        checkGetStake(blsPubKeys[0], depositAmount + topUpAmount);
    }

    function test_unstake_withdraw() public {
        uint256 ownerInt = 0;
        uint256 depositAmount = 20 ether;
        deposit(ownerInt, depositAmount);

        // Roll ahead 2 epochs
        vm.roll(block.number + depositContract.blocksPerEpoch() * 2);

        checkGetStake(blsPubKeys[ownerInt], depositAmount);

        // Unstake twice - these two should roll into the same withdrawal
        uint256 unstakeAmount1 = 3 ether;
        unstake(0, unstakeAmount1);
        uint256 unstakeAmount2 = 1 ether;
        unstake(0, unstakeAmount2);

        checkGetStake(blsPubKeys[ownerInt], depositAmount);
        checkGetFutureStake(
            blsPubKeys[ownerInt],
            depositAmount - unstakeAmount1 - unstakeAmount2
        );
        checkGetStakerDataWithdrawals(blsPubKeys[ownerInt], 1);

        // Roll ahead one block
        vm.roll(block.number + 1);

        // Unstake again
        uint256 unstakeAmount3 = 4 ether;
        unstake(0, unstakeAmount3);

        checkGetStake(blsPubKeys[ownerInt], depositAmount);
        checkGetFutureStake(
            blsPubKeys[ownerInt],
            depositAmount - unstakeAmount1 - unstakeAmount2 - unstakeAmount3
        );
        // should now be 2 withdrawals
        checkGetStakerDataWithdrawals(blsPubKeys[ownerInt], 2);

        // Roll ahead withdrawal period
        vm.roll(block.number + depositContract.withdrawalPeriod());

        checkGetStake(
            blsPubKeys[ownerInt],
            depositAmount - unstakeAmount1 - unstakeAmount2 - unstakeAmount3
        );

        // Withdraw only one of the unstakings
        uint256 balanceBefore = owners[ownerInt].balance;
        withdraw(ownerInt, 1);

        assertEq(
            balanceBefore + unstakeAmount1 + unstakeAmount2,
            owners[ownerInt].balance
        );
    }

    function test_getters() public {
        // bytes[] storage expected_stakerKeys = expected_stakerKeys_storage;
        // uint256[] storage expected_indices = expected_indices_storage;
        // uint256[] storage expected_amounts = expected_amounts_storage;
        // checkGetStakersData(expected_stakerKeys, expected_indices,  expected_amounts);

        // Deposit owner 0
        uint256 depositOwner0Amount = 20 ether;
        deposit(0, depositOwner0Amount);

        checkGetStake(blsPubKeys[0], 0);
        checkGetFutureStake(blsPubKeys[0], depositOwner0Amount);
        checkGetTotalStake(0);
        checkGetTotalFutureStake(depositOwner0Amount);
        checkGetStakerData(blsPubKeys[0], 0, 0);
        // checkGetStakersData(expected_stakerKeys, expected_indices,  expected_amounts);

        // Roll ahead 2 epochs
        vm.roll(block.number + depositContract.blocksPerEpoch() * 2);

        checkGetStake(blsPubKeys[0], depositOwner0Amount);
        checkGetFutureStake(blsPubKeys[0], depositOwner0Amount);
        checkGetTotalStake(depositOwner0Amount);
        checkGetTotalFutureStake(depositOwner0Amount);
        checkGetStakerData(blsPubKeys[0], 1, depositOwner0Amount);
        // expected_stakerKeys.push(blsPubKeys[0]);
        // expected_indices.push(uint256(0));
        // expected_amounts.push(depositOwner0Amount);
        // checkGetStakersData(expected_stakerKeys, expected_indices, expected_amounts);

        // Deposit owner 1
        uint256 depositOwner1Amount = 10 ether;
        deposit(1, depositOwner1Amount);

        checkGetStake(blsPubKeys[1], 0);
        checkGetFutureStake(blsPubKeys[1], depositOwner1Amount);
        checkGetTotalStake(depositOwner0Amount);
        checkGetTotalFutureStake(depositOwner0Amount + depositOwner1Amount);
        checkGetStakerData(blsPubKeys[0], 1, depositOwner0Amount);
        checkGetStakerData(blsPubKeys[1], 0, 0);
        // checkGetStakersData(expected_stakerKeys, expected_indices, expected_amounts);

        // Roll ahead 2 epochs
        vm.roll(block.number + depositContract.blocksPerEpoch() * 2);

        checkGetStake(blsPubKeys[1], depositOwner1Amount);
        checkGetFutureStake(blsPubKeys[1], depositOwner1Amount);
        checkGetTotalStake(depositOwner0Amount + depositOwner1Amount);
        checkGetTotalFutureStake(depositOwner0Amount + depositOwner1Amount);
        checkGetStakerData(blsPubKeys[0], 1, depositOwner0Amount);
        checkGetStakerData(blsPubKeys[1], 2, depositOwner1Amount);

        // getRewardAddress
        assertEq(depositContract.getRewardAddress(blsPubKeys[0]), stakers[0]);
        assertEq(depositContract.getRewardAddress(blsPubKeys[1]), stakers[1]);
        // getSigningAddress
        assertEq(depositContract.getSigningAddress(blsPubKeys[0]), stakers[0]);
        assertEq(depositContract.getSigningAddress(blsPubKeys[1]), stakers[1]);
        // getControlAddress
        assertEq(depositContract.getSigningAddress(blsPubKeys[0]), stakers[0]);
        assertEq(depositContract.getSigningAddress(blsPubKeys[1]), stakers[1]);
        // getPeerId
        assertEq(depositContract.getPeerId(blsPubKeys[0]), peerId);
        assertEq(depositContract.getPeerId(blsPubKeys[1]), peerId);
    }

    function checkGetStake(
        bytes memory blsPubKey,
        uint256 expectedAmount
    ) public view {
        uint256 gasBefore = gasleft();
        uint256 stake = depositContract.getStake(blsPubKey);
        if (printGasUsage) {
            console.log(
                "\ngetStake(): %s   Gas used: %s",
                stake,
                gasBefore - gasleft()
            );
        }
        assertEq(stake, expectedAmount);
    }

    function checkGetTotalStake(uint256 expectedAmount) public view {
        uint256 gasBefore = gasleft();
        uint256 totalStake = depositContract.getTotalStake();
        if (printGasUsage) {
            console.log(
                "\ngetTotalStake(): %s   Gas used: %s",
                totalStake,
                gasBefore - gasleft()
            );
        }
        assertEq(totalStake, expectedAmount);
    }

    function checkGetFutureStake(
        bytes memory blsPubKey,
        uint256 expectedAmount
    ) public view {
        uint256 gasBefore = gasleft();
        uint256 stake = depositContract.getFutureStake(blsPubKey);
        if (printGasUsage) {
            console.log(
                "\ngetFutureStake(): %s   Gas used: %s",
                stake,
                gasBefore - gasleft()
            );
        }
        assertEq(stake, expectedAmount);
    }

    function checkGetTotalFutureStake(uint256 expectedAmount) public view {
        uint256 gasBefore = gasleft();
        uint256 totalStake = depositContract.getFutureTotalStake();
        if (printGasUsage) {
            console.log(
                "\ngetFutureTotalStake(): %s   Gas used: %s",
                totalStake,
                gasBefore - gasleft()
            );
        }
        assertEq(totalStake, expectedAmount);
    }

    function checkGetStakerData(
        bytes memory blsPubKey,
        uint256 expectedIndex,
        uint256 expectedBalance // Staker memory expectedStakers
    ) public view {
        uint256 gasBefore = gasleft();
        (
            uint256 index,
            uint256 balance, // Staker memory stakerData

        ) = depositContract.getStakerData(blsPubKey);
        if (printGasUsage) {
            console.log("\ngetStakerData Gas used: %s", gasBefore - gasleft());
        }
        assertEq(index, expectedIndex);
        assertEq(balance, expectedBalance);
        // assertEq(stakerData[i], expectedStakers[i]);
    }

    function checkGetStakerDataWithdrawals(
        bytes memory blsPubKey,
        uint256 withdrawals
    ) public view {
        uint256 gasBefore = gasleft();
        (, , Deposit.StakerData memory stakerData) = depositContract
            .getStakerData(blsPubKey);
        if (printGasUsage) {
            console.log("\ngetStakerData Gas used: %s", gasBefore - gasleft());
        }
        assertEq(stakerData.withdrawals.length, withdrawals);
    }

    // function checkGetStakersData(
    //     bytes[] memory expected_stakerKeys,
    //     uint256[] memory expected_indices,
    //     uint256[] memory expectedBalances
    //     // Staker[] memory expectedStakers
    // ) public view {
    //     uint256 gasBefore = gasleft();
    // (
    //     bytes[] memory stakerKeys,
    //     uint256[] memory indices,
    //     uint256[] memory balances,
    //     // Staker[] memory stakerData
    // ) = deposit_contract.getStakersData();
    // if (print_gas_usage) {
    //     console.log("\ngetStakersData length: %s Gas used: %s", stakerKeys.length, gasBefore - gasleft());
    // }
    // for (uint256 i = 0; i < stakerKeys.length; i++) {
    //     assertEq(stakerKeys[i], expected_stakerKeys[i]);
    //     assertEq(indices[i], expected_indices[i]);
    //     assertEq(balances[i], expectedBalances[i]);

    //     // assertEq(stakerData[i], expectedStakers[i]);
    //     console.log("stakerKey");
    //     console.logBytes(stakerKeys[i]);
    //     console.log("indices %s", indices[i]);
    //     console.log("balances %s", balances[i]);
    // }
    // }

    function deposit(uint ownerInt, uint amount) public {
        vm.startPrank(owners[ownerInt]);
        uint256 gasBefore = gasleft();
        depositContract.deposit{value: amount}(
            blsPubKeys[ownerInt],
            peerId,
            bytes(
                hex"90ec9a22e030a42d9b519b322d31b8090f796b3f75fc74261b04d0dcc632fd8c5b7a074c5ba61f0845b310fa9931d01c079eebe82813d7021ef4172e01a7d3710a5f9a4634e9a03a51e985836021c356a1eb476a14f558cbae1f4264edca5dac"
            ),
            address(stakers[ownerInt]),
            address(stakers[ownerInt])
        );
        if (printGasUsage) {
            console.log(
                "\ndeposit owner%s. Amount: %s   Gas used: %s",
                ownerInt,
                amount,
                gasBefore - gasleft()
            );
        }
    }

    function depositTopUp(uint ownerInt, uint amount) public {
        vm.startPrank(owners[ownerInt]);
        uint256 gasBefore = gasleft();
        depositContract.depositTopup{value: amount}(blsPubKeys[ownerInt]);
        if (printGasUsage) {
            console.log(
                "\ndepositTopUp owner%s. Amount: %s Gas used: %s",
                ownerInt,
                amount,
                gasBefore - gasleft()
            );
        }
    }

    function unstake(uint ownerInt, uint amount) public {
        vm.startPrank(owners[ownerInt]);
        uint256 gasBefore = gasleft();
        depositContract.unstake(blsPubKeys[ownerInt], amount);
        if (printGasUsage) {
            console.log(
                "\nunstake owner%s. Amount: %s Gas used: %s",
                ownerInt,
                amount,
                gasBefore - gasleft()
            );
        }
    }

    function withdraw(uint ownerInt, uint count) public {
        vm.startPrank(owners[ownerInt]);
        uint256 gasBefore = gasleft();
        depositContract.withdraw(blsPubKeys[ownerInt], count);
        if (printGasUsage) {
            console.log(
                "\nwithdraw owner%s. Count: %s Gas used: %s",
                ownerInt,
                count,
                gasBefore - gasleft()
            );
        }
    }
}
