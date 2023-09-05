// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "@openzeppelin/contracts/access/Ownable.sol";

contract GasPrice is Ownable {

    uint public value;

    constructor() {
        value = 1000;
    }

    function setGas(uint to) public onlyOwner {
        value = to;
    }
}
