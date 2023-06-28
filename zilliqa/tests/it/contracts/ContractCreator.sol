// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.20;

contract CreateMe {}

contract Creator {
    // Emit the created address as an event, so we can see it in the receipt.
    event Created(address indexed addr);

    CreateMe created;

    function create() external {
        created = new CreateMe();
        emit Created(address(created));
    }
}
