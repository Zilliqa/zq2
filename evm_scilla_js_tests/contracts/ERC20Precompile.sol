// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.7 <0.9.0;

contract ERC20Precompile {
  address public constant ERC20_ADDRESS = 0x00000000000000000000000000000000005A494C;

  function balanceOf(address account) public view virtual returns (uint256 funds) {
    bytes4 selector = bytes4(keccak256("balanceOf(address)"));

    bytes memory encodedArgs = abi.encodeWithSelector(selector, account);
    uint256 argsLength = encodedArgs.length;

    bytes memory output = new bytes(36);

    bool success;
    assembly {
      success := staticcall(21000, ERC20_ADDRESS, add(encodedArgs, 0x20), argsLength, add(output, 0x20), 32)
    }
    (funds) = abi.decode(output, (uint256));
    return funds;
  }
}
