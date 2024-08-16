// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;
import "contracts/core/ChainGateway.sol";

contract Target {
    uint public count;
    ChainGateway public gateway;

    event Incremented(uint count);

    constructor(address gatewayContract) {
        gateway = ChainGateway(gatewayContract);
    }

    function foo() external pure returns (string memory) {
        return "hello world";
    }

    function increment() external returns (uint) {
        emit Incremented(++count);
        return count;
    }
}
