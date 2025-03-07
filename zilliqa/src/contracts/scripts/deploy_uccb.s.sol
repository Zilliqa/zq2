// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import "forge-std/console.sol";
import { ValidatorManager } from "../uccb/ValidatorManager.sol";
import { ChainGateway } from "../uccb/ChainGateway.sol";
import { ERC1967Proxy } from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";


contract DeployUCCB is Script {
  function run() external {
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY_OWNER");
    address owner = vm.addr(deployerPrivateKey);
    console.log("owner = %s", owner);
    bytes32 salt = vm.envBytes32("SALT");
    //address[] memory validators = vm.envAddress("VALIDATORS", ",");
    address[] memory validators = new address[](0);
    vm.startBroadcast(deployerPrivateKey);
    address vmImplementation = address(new ValidatorManager{salt: salt}());
    bytes memory vmInitCall = abi.encodeWithSelector(
        ValidatorManager.initialize.selector,
        owner,
        validators);
    address vmProxyAddress = address(new ERC1967Proxy{salt: salt}(vmImplementation, vmInitCall));
    console.log("validator_manager = %s",vmProxyAddress);
    address cgImplementation = address(new ChainGateway{salt: salt}());
    bytes memory cgInitCall = abi.encodeWithSelector(
        ChainGateway.initialize.selector,
        vmProxyAddress,
        owner);
    address cgProxyAddress = address(new ERC1967Proxy{salt: salt}(cgImplementation, cgInitCall));
    console.log("chain gateway = %s", cgProxyAddress);
    vm.stopBroadcast();
  }
}
