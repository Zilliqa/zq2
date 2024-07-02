// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Storage {
    uint pos0;
    mapping(address => uint) public pos1;
    constructor() {
        pos0 = 1234;
        pos1[msg.sender] = 5678;
    }

    function update() public {
        pos0 = 9876;
    }

    function set(address key, uint val) public {
        pos1[key] = val;
    }
}
