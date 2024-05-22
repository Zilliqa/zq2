// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

contract GasTestCreate {
    address public test;

    function deploy() public {
        test = address(new GasTestCreatedContract());
        require(test != address(0));
    }

    function deploy2(uint256 _salt) public {
        test = address(new GasTestCreatedContract{salt: bytes32(_salt)}());
        require(test != address(0));
    }
}

contract GasTestCreatedContract {}