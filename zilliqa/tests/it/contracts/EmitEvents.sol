// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.20;

contract EmitEvents {
    // Two random events from common tokens.
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    function emitEvents() public {
        // Same in the first argument, differ in the second and third arguments.
        emit Transfer(0x0000000000000000000000000000000000000001, 0x0000000000000000000000000000000000000002, 444);
        emit Approval(0x0000000000000000000000000000000000000001, 0x0000000000000000000000000000000000000003, 555);
    }
}
