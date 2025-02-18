// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.26;
import {Deposit, Staker} from "../deposit_v5.sol";
import {DepositInit, InitialStaker} from "../deposit_v1.sol";
import {Test, Vm, console2 as console} from "@openzeppelin/lib/forge-std/src/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Testing contract for deposit_v4 development

contract PopVerifyPrecompile {
    function popVerify(bytes memory, bytes memory) public pure returns(bool) {
        return true;
    }
}

contract BlsVerifyPrecompile {
    function blsVerify(bytes memory, bytes memory, bytes memory) public pure returns(bool) {
        return true;
    }
}

contract DepositTest is Test {
    address payable proxy;
    DepositInit deposit_init_contract;
    Deposit deposit_contract;
    uint8 contract_version = 5;
    bool print_gas_usage = true;
    address owner1 = vm.addr(uint256(1));
    address owner2 = vm.addr(uint256(2));
    address[4] stakers = [
        0xd819fFcE7A58b1E835c25617Db7b46a00888B013,
        0x092E5E57955437876dA9Df998C96e2BE19341670,
        0xeA78aAE5Be606D2D152F00760662ac321aB8F017,
        0x6603A37980DF7ef6D44E994B3183A15D0322B7bF
    ];
    bytes blsPubKey1 = bytes(hex"92370645a6ad97d8a4e4b44b8e6db63ab8409473310ac7b21063809450192bace7fb768d60c697a18bbf98b4ddb511f1");
    bytes blsPubKey2 = bytes(hex"92370645a6ad97d8a4e4b44b8e6db63ab8409473310ac7b21063809450192bace7fb768d60c697a18bbf98b4ddb511f2");

    constructor() {
    }

    function test_Deposit() public {
        vm.chainId(33469);
        vm.deal(owner1, 40_000_000 ether);
        vm.deal(owner2, 40_000_000 ether);

        vm.deal(stakers[0], 0);
        vm.deal(stakers[1], 0);
        vm.deal(stakers[2], 0);

        vm.startPrank(address(0));

        // Deploy initial version
        address deposit_contract_initial_addr = address(new DepositInit());
        deposit_init_contract = DepositInit(deposit_contract_initial_addr);

        bytes memory initializerCall = abi.encodeWithSignature(
            "initialize(uint256,uint256,uint64,(bytes,bytes,address,address,uint256)[])",
            uint256(10 ether),
            uint256(256),
            uint64(10),
            new InitialStaker[](0)
        );
        proxy = payable(
            new ERC1967Proxy(deposit_contract_initial_addr, initializerCall)
        );
        deposit_init_contract = DepositInit(proxy);

        // Upgrade to deposit_v5
        address deposit_contract_addr = address(new Deposit());
        uint256 withdrawalPeriod = uint256(36);
        bytes memory reinitializerCall = abi.encodeWithSignature(
            "reinitialize(uint256)",
            withdrawalPeriod
        );
        deposit_init_contract.upgradeToAndCall(
            deposit_contract_addr,
            reinitializerCall
        );
        deposit_contract = Deposit(proxy);

        // Other setup
        vm.etch(address(0x5a494c81), address(new BlsVerifyPrecompile()).code);


        // Confirm upgrade 
        assertEq(deposit_contract.version(), contract_version);
        assertEq(deposit_contract.withdrawalPeriod(), withdrawalPeriod);
    }

    function checkGetStake(bytes memory blsPubKey, uint256 expected_amount) view public {
        uint256 gasBefore = gasleft();
        uint256 stake = deposit_contract.getStake(blsPubKey);
        if (print_gas_usage) {
            console.log("\ngetStake(): %s   Gas used: %s", stake, gasBefore - gasleft());
        }
        assertEq(stake, expected_amount);
    }

    function checkGetTotalStake(uint256 expected_amount) public {
        uint256 gasBefore = gasleft();
        uint256 total_stake = deposit_contract.getTotalStake();
        if (print_gas_usage) {
            console.log("\ngetTotalStake(): %s   Gas used: %s", total_stake, gasBefore - gasleft());
        }
        assertEq(total_stake, expected_amount);
    }

    function checkGetFutureStake(bytes memory blsPubKey, uint256 expected_amount) view public {
        uint256 gasBefore = gasleft();
        uint256 stake = deposit_contract.getFutureStake(blsPubKey);
        if (print_gas_usage) {
            console.log("\ngetFutureStake(): %s   Gas used: %s", stake, gasBefore - gasleft());
        }
        assertEq(stake, expected_amount);
    }

    function checkGetTotalFutureStake(uint256 expected_amount) view public {
        uint256 gasBefore = gasleft();
        uint256 total_stake = deposit_contract.getFutureTotalStake();
        if (print_gas_usage) {
            console.log("\ngetFutureTotalStake(): %s   Gas used: %s", total_stake, gasBefore - gasleft());
        }
        assertEq(total_stake, expected_amount);
    }

    function getStakersData(bytes[] memory expected_stakerKeys, uint256[] memory expected_indices, uint256[] memory expected_balances, Staker[] memory expected_stakers) view public {
        uint256 gasBefore = gasleft();
        (
            bytes[] memory stakerKeys,
            uint256[] memory indices,
            uint256[] memory balances,
            Staker[] memory stakers
        ) = deposit_contract.getStakersData();
        if (print_gas_usage) {
            console.log("\ngetStakersData length: %s Gas used: %s", stakerKeys.length, gasBefore - gasleft());
        }
        for (uint256 i = 0; i < stakerKeys.length; i++) {
            assertEq(stakerKeys[i], expected_stakerKeys[i]);
            assertEq(indices[i], expected_indices[i]);
            assertEq(balances[i], expected_balances[i]);

            // assertEq(stakers[i], expected_stakers[i]);
            console.log("stakerKey");
            console.logBytes(stakerKeys[i]);
            console.log("indices %s", indices[i]);
            console.log("balances %s", balances[i]);        
        }
    }

    function depositTopUp(uint ownerInt, uint amount) public {
        address owner;
        bytes memory blsPubKey;
        if (ownerInt == 1) {
            owner = owner1;
            blsPubKey = blsPubKey1;
        } else {
            owner = owner2;
            blsPubKey = blsPubKey2;
        }
        vm.startPrank(owner);
        uint256 gasBefore = gasleft();
        deposit_contract.depositTopup{
            value: amount
        }(blsPubKey);
        console.log("\ndepositTopUp owner%s. Amount: %s Gas used: %s", ownerInt, amount, gasBefore - gasleft());
        vm.stopPrank();
    }
}