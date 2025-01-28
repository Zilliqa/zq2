import { expect } from "chai";
import {ScillaContract} from "hardhat-scilla-plugin";
import hre, { ethers } from "hardhat";
import { createHash } from "crypto";
import { Account, Zilliqa } from "@zilliqa-js/zilliqa";
import { getZilBalance } from "../../helpers/SignersHelper";

function getContractAddress(sender: string, nonce: number): string {
    const senderBytes = Buffer.from(sender.replace('0x', ''), 'hex');
    const nonceBytes = Buffer.alloc(8);
    nonceBytes.writeBigUInt64BE(BigInt(nonce));
    return "0x" + createHash("sha256").update(Buffer.concat([senderBytes, nonceBytes])).digest("hex").slice(-40);
}

async function getNonce(address: string): Promise<number> {
    const zilliqa = new Zilliqa(hre.getNetworkUrl());
    const balance = await zilliqa.blockchain.getBalance(address);
    return balance.result.nonce;
}

describe("Already funded contract address", () => {
  let contract: ScillaContract;
  let signer: Account;
  const AMOUNT = ethers.utils.parseUnits("1", "gwei");

  before(async () => {
    signer = hre.allocateZilSigner();
    const contractAddress = getContractAddress(signer.address, await getNonce(signer.address));
    const funder = hre.allocateEthSigner();
    const tx = await funder.sendTransaction({to: contractAddress, value: AMOUNT});
    await tx.wait();
    contract = await hre.deployScillaContractWithSigner("BlockNumber", signer);
  });

  it("contract should have its previous zils", async () => {
    const balance = await getZilBalance(hre, contract.address!);
    expect(balance).to.be.eq(AMOUNT.div(1_000_000));
  });
});
