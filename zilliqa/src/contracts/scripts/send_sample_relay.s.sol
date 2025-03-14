// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Tester} from "../test/Tester.sol";
import {ChainGateway} from "../uccb/ChainGateway.sol";
import {Script} from "forge-std/Script.sol";
import "forge-std/console.sol";

contract SendSampleRelay is Script {
  function run() external {
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY_OWNER");
    address deployerAddress = vm.addr(deployerPrivateKey);
    ChainGateway gateway = ChainGateway(vm.envAddress("CHAIN_GATEWAY_ADDRESS"));
    vm.startBroadcast(deployerPrivateKey);
    gateway.register(deployerAddress);
    gateway.relayWithMetadata(
        0x123456,
        address(0x1),
        SendSampleRelay.run.selector,
        "",
        1_000_000);
    vm.stopBroadcast();
  }
}
