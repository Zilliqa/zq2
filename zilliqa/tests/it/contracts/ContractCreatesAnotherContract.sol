// SPDX-License-Identifier: Apache-2.0 OR MIT
pragma solidity ^0.8.20;

contract Creator {
    event Created(CreateMe createMe);

    function create() public {
        CreateMe createMe = new CreateMe();
        emit Created(createMe);
    }
}

contract CreateMe {}
