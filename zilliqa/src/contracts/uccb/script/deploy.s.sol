// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {ValidatorManager} from "contracts/ValidatorManager.sol";
import "forge-std/console.sol";

contract Deployment is Script {
    function run() external {
        uint256 ownerPrivateKey = vm.envUint("OWNER_PRIVATE_KEY");

        vm.startBroadcast(ownerPrivateKey);

        ValidatorManager validatorManager = new ValidatorManager{salt: "salt"}(
            vm.addr(ownerPrivateKey)
        );

        // The validator oracle will update the validators upon startup
        address[] memory validators = new address[](0);
        validatorManager.initialize(validators);

        vm.stopBroadcast();
    }
}
