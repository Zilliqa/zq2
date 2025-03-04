// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Tester} from "../../test/Tester.sol";
import {ValidatorManager} from "../../uccb/ValidatorManager.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract ValidatorManagerTests is Tester {
    address owner = vm.createWallet("Owner").addr;
    address validator1 = vm.createWallet("Validator1").addr;
    address validator2 = vm.createWallet("Validator2").addr;
    ValidatorManager validatorManager;

    function setUp() external {
        address[] memory validators = new address[](1);
        validators[0] = validator1;

        vm.prank(owner);
        address implementation = address(new ValidatorManager());
        address proxy = address(
            new ERC1967Proxy(
                implementation,
                abi.encodeWithSelector(
                    ValidatorManager.initialize.selector,
                    address(owner),
                    validators
                )
            )
        );
        validatorManager = ValidatorManager(proxy);
    }

    function test_addValidator() external {
        vm.startPrank(owner);
        validatorManager.addValidator(validator2);

        assertEq(validatorManager.validatorsSize(), 2);
        assertEq(validatorManager.isValidator(validator1), true);
        assertEq(validatorManager.isValidator(validator2), true);
        vm.stopPrank();
    }

    function test_removeValidator() external {
        vm.startPrank(owner);
        validatorManager.removeValidator(validator1);

        assertEq(validatorManager.validatorsSize(), 0);
        assertEq(validatorManager.isValidator(validator1), false);
        vm.stopPrank();
    }

    function test_revertAddValidatorIfNotOwner() external {
        address nonOwner = vm.createWallet("NonOwner").addr;

        vm.prank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                nonOwner
            )
        );
        validatorManager.addValidator(validator2);
    }

    function test_revertRemoveValidatorIfNotOwner() external {
        address nonOwner = vm.createWallet("NonOwner").addr;

        vm.prank(nonOwner);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                nonOwner
            )
        );
        validatorManager.removeValidator(validator2);
    }

    function test_transferOwnership() external {
        address newOwner = vm.createWallet("NewOwner").addr;

        vm.prank(owner);
        validatorManager.transferOwnership(newOwner);
        // Ownership should only be transferred after newOwner accepts
        assertEq(validatorManager.owner(), owner);

        vm.prank(newOwner);
        validatorManager.acceptOwnership();
        assertEq(validatorManager.owner(), newOwner);
    }
}
