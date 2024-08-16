// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {ChainGateway} from "contracts/core/ChainGateway.sol";
import {Target} from "test/Target.sol";

contract Relay is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address chainGateway = vm.envAddress("CHAIN_GATEWAY_ADDRESS");
        address target = vm.envAddress("TARGET_ACCOUNT_ADDRESS");
        uint targetChainId = vm.envUint("TARGET_CHAIN_ID");

        vm.startBroadcast(deployerPrivateKey);

        ChainGateway(chainGateway).relay(
            targetChainId,
            target,
            abi.encodeWithSelector(Target.increment.selector),
            1_000_000
        );

        vm.stopBroadcast();
    }
}

