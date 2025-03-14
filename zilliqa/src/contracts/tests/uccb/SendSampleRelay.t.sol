// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

import {Tester} from "../../test/Tester.sol";
import {ChainGateway} from "../../uccb/ChainGateway.sol";

contract SendSampleRelayTests is Tester {
  uint256 senderPrivateKey;
  ChainGateway gateway;
  
  function setUp() external {
    senderPrivateKey = vm.envUint("PRIVATE_KEY_OWNER");
    gateway = ChainGateway(vm.envAddress("CHAIN_GATEWAY_ADDRESS"));
  }

  
    
    

}
