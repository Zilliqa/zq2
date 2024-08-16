// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.20;

abstract contract Registry {
    mapping(address => bool) public registered;

    error NotRegistered(address targetAddress);

    modifier isRegistered(address target) {
        if (!registered[target]) {
            revert NotRegistered(target);
        }
        _;
    }

    function _register(address newTarget) internal {
        registered[newTarget] = true;
    }

    function _unregister(address removeTarget) internal {
        registered[removeTarget] = false;
    }

    function register(address newTarget) external virtual;

    function unregister(address removeTarget) external virtual;
}
