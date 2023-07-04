// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract SetGetContractValue {
  int256 private value = 99;

  constructor() {}

  function getInt256() public view returns (int256) {
    return value;
  }

  function setInt256(int256 _value) public {
    value = _value;
  }
}
