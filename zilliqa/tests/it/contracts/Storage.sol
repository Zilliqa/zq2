// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;
contract Storage {
    uint pos0;
    mapping(address => uint) pos1;
    constructor() {
        pos0 = 1234;
        pos1[msg.sender] = 5678;
    }
}
