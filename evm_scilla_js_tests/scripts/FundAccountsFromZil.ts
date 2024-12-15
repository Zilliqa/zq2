import hre from "hardhat";
import clc from "cli-color";
import {bytes, toChecksumAddress, Zilliqa} from "@zilliqa-js/zilliqa";
import {getAddressFromPrivateKey} from "@zilliqa-js/crypto";
import {BN, Long} from "@zilliqa-js/util";
import {ethers} from "ethers";

async function main() {
  const provider = hre.ethers.provider;

  // Constants needed for ZIL transfer
  const msgVersion = 1; // current msgVersion
  const VERSION = bytes.pack(await hre.getZilliqaChainId(), msgVersion);

  const accounts: string[] = await provider.send("eth_accounts", []);
  let balances = await Promise.all(
    accounts.map((account: string) => provider.send("eth_getBalance", [account, "latest"]))
  );

  // Print balances of ETH accounts before
  accounts.forEach((element, index) => {
    console.log(
      clc.bold("Account"),
      clc.green(element),
      clc.bold("Initial balance:"),
      clc.greenBright(balances[index])
    );
  });

  const private_keys: string[] = hre.network["config"]["accounts"] as string[];
  for (const element of private_keys) {
    console.log("");
    console.log("Starting transfer...");

    // Get corresponding ETH account
    let ethAddr = new ethers.Wallet(element, provider);
    let ethAddrConverted = toChecksumAddress(ethAddr.address); // ZIL checksum
    let initialAccountBal = await ethAddr.getBalance();
    console.log("Account to send to (ZIL checksum): ", ethAddrConverted);
    console.log("Account to send to, initial balance: ", initialAccountBal.toString());

    // Transfer half funds to this account
    let zilliqa = new Zilliqa(hre.getNetworkUrl());
    zilliqa.wallet.addByPrivateKey(element);
    const address = getAddressFromPrivateKey(element);
    console.log(`My ZIL account address is: ${address}`);

    const res = await zilliqa.blockchain.getBalance(address);

    if (res.error?.message) {
      console.log("Error: ", res.error);
      console.log("Skipping account with error");
      continue;
    }
    const balance = res.result.balance;

    console.log(`My ZIL account balance is: ${balance}`);

    if (balance == 0) {
      console.log("Skipping account with 0 balance");
      continue;
    }

    const gasp = await provider.getGasPrice();
    const gasPrice = new BN(gasp.toString());

    const tx = await zilliqa.blockchain.createTransactionWithoutConfirm(
      zilliqa.transactions.new(
        {
          version: VERSION,
          toAddr: ethAddrConverted,
          amount: new BN(balance).div(new BN(2)), // Sending an amount in ZIL (1) and converting the amount to Qa
          gasPrice: gasPrice, // Minimum gasPrice varies. Check the `GetMinimumGasPrice` on the blockchain
          gasLimit: Long.fromNumber(2100)
        },
        false
      )
    );

    // Process confirmation
    if (tx.id) {
      console.log(`The transaction id is:`, tx.id);
      const confirmedTxn = await tx.confirm(tx.id);

      console.log(`The transaction status is:`);
      console.log(confirmedTxn.getReceipt());

      let finalBal = await ethAddr.getBalance();
      console.log(`My new account balance is: ${finalBal.toString()}`);
    } else {
      console.log("Failed");
    }
  }

  balances = await Promise.all(accounts.map((account: string) => provider.send("eth_getBalance", [account, "latest"])));

  // Print balances of ETH accounts after
  accounts.forEach((element, index) => {
    console.log(clc.bold("Account"), clc.green(element), clc.bold("Final balance:"), clc.greenBright(balances[index]));
  });
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
