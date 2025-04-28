import {BN, Zilliqa, getAddressFromPrivateKey, units} from "@zilliqa-js/zilliqa";
import {BigNumber} from "ethers";
import {ethers} from "ethers";
import {HardhatRuntimeEnvironment} from "hardhat/types";
import fs from "fs";

/// HRE CAN'T BE IMPORTED, BECAUSE THIS FUNCTIONS ARE USED IN TASKS, IT SHOULD BE PASSED AS AN ARGUMENT.

export enum AccountType {
  EthBased = "eth",
  ZilBased = "zil"
}

export type Account = {
  type: AccountType;
  private_key: string;
};

export const getEthBalance = async (
  hre: HardhatRuntimeEnvironment,
  privateKey: string
): Promise<[address: string, balance: BigNumber]> => {
  const wallet = new ethers.Wallet(privateKey, hre.ethers.provider);
  return [wallet.address.toLowerCase(), await wallet.getBalance()];
};

export const getZilBalanceByPrivateAddress = async (
  hre: HardhatRuntimeEnvironment,
  privateKey: string
): Promise<[address: string, balance: BN]> => {
  const address = getAddressFromPrivateKey(privateKey);
  let zilliqa = new Zilliqa(hre.getNetworkUrl());

  const balanceResult = await zilliqa.blockchain.getBalance(address);
  if (balanceResult.error) {
    return [address.toLowerCase(), new BN(0)];
  } else {
    return [address.toLowerCase(), new BN(balanceResult.result.balance)];
  }
};

export const getZilBalance = async (hre: HardhatRuntimeEnvironment, address: string): Promise<BN> => {
  let zilliqa = new Zilliqa(hre.getNetworkUrl());
  const balanceResult = await zilliqa.blockchain.getBalance(address);

  if (balanceResult.error) {
    return new BN(0);
  }

  return new BN(balanceResult.result.balance);
};

export async function getNonce(hre: HardhatRuntimeEnvironment, address: string): Promise<number> {
  let zilliqa = new Zilliqa(hre.getNetworkUrl());
  const balance = await zilliqa.blockchain.getBalance(address);
  return balance.result.nonce as number;
}

export const getZilAddress = (privateKey: string): string => {
  return getAddressFromPrivateKey(privateKey).toLowerCase();
};

export const getEthAddress = (privateKey: string): string => {
  const wallet = new ethers.Wallet(privateKey);
  return wallet.address;
};

export const loadFromSignersFile = (network_name: string): string[] => {
  try {
    return JSON.parse(fs.readFileSync(`.signers/${network_name}.json`, "utf8"));
  } catch (error) {
    return [];
  }
};

export const loadSignersFromConfig = (hre: HardhatRuntimeEnvironment): string[] => {
  return hre.network["config"]["accounts"] as string[];
};

export const getAllSigners = (hre: HardhatRuntimeEnvironment): string[] => {
  return loadSignersFromConfig(hre);
};

export const getEthSignersBalances = async (
  hre: HardhatRuntimeEnvironment
): Promise<[address: string, balance: BigNumber][]> => {
  const signers = getAllSigners(hre);

  let promises = signers.map((signer) => getEthBalance(hre, signer));
  return await Promise.all(promises);
};

export const getZilSignersBalances = async (
  hre: HardhatRuntimeEnvironment
): Promise<[address: string, balance: BN][]> => {
  const signers = getAllSigners(hre);

  let promises = signers.map((signer) => getZilBalanceByPrivateAddress(hre, signer));
  return await Promise.all(promises);
};
