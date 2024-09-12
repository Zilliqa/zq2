import {BN, bytes, getAddressFromPrivateKey, units, Zilliqa} from "@zilliqa-js/zilliqa";
import {ethers} from "ethers";
import Long from "long";

export interface Account {
  privateKey: string;
  ethAddress: string;
  zilAddress: string;
}

export function generateAccount(): Account {
  const newAccount = ethers.Wallet.createRandom();
  const zilAddress = getAddressFromPrivateKey(newAccount.privateKey);
  return {
    privateKey: newAccount.privateKey,
    zilAddress,
    ethAddress: newAccount.address
  };
}

export async function createAndFundAccounts(zilliqa: Zilliqa, numberOfAccounts: number): Promise<Account[]> {
  const accounts: Account[] = [];
  const fundingAmount = units.toQa("0.1", units.Units.Zil);

  for (let i = 0; i < numberOfAccounts; i++) {
    const account = generateAccount();
    accounts.push(account);

    await fundAccount(zilliqa, account.zilAddress, fundingAmount);
  }

  return accounts;
}

export async function fundAccount(zilliqa: Zilliqa, address: string, amount: BN, nonce?: number) {
  await zilliqa.blockchain.createTransaction(
    zilliqa.transactions.new({
      version: bytes.pack(1, 1),
      toAddr: address,
      amount,
      nonce,
      gasPrice: units.toQa("2000", units.Units.Li),
      gasLimit: Long.fromNumber(2100)
    })
  );
}

export async function getNonce(zilliqa: Zilliqa, address: string): Promise<number> {
  const balance = await zilliqa.blockchain.getBalance(address);
  return balance.result.nonce as number;
}
