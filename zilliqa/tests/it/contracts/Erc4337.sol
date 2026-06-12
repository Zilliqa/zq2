// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract Erc4337 {
    constructor() {}

    function getBalance() public view returns (uint256) {
        return address(this).balance; // checks state overrides
    }

    function getNumber() public view returns (uint256) {
        return block.number; // not allowed in ERC4337
    }
}
