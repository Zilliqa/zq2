// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {ChainGateway} from "contracts/core/ChainGateway.sol";

contract Register is Script {
    function run() external {
        uint256 ownerPrivateKey = vm.envUint("OWNER_PRIVATE_KEY");
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address chainGateway = vm.envAddress("CHAIN_GATEWAY_ADDRESS");

        vm.startBroadcast(ownerPrivateKey);

        address deployer = vm.addr(deployerPrivateKey);
        ChainGateway(chainGateway).register(deployer);

        vm.stopBroadcast();
    }
}

