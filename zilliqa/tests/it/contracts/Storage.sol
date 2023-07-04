// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;
contract Storage {
    uint pos0;
    mapping(address => uint) pos1;
    constructor() {
        pos0 = 1234;
        pos1[msg.sender] = 5678;
    }

    function update() public {
        pos0 = 9876;
    }
}
