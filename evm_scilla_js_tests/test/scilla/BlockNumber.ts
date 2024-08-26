const {expect} = require("chai");
import {ScillaContract} from "hardhat-scilla-plugin";
import hre from "hardhat";
import {Account} from "@zilliqa-js/zilliqa";

describe("BlockNumber contract #parallel", () => {
  let contract: ScillaContract;
  let signer: Account;

  before(async () => {
    signer = hre.allocateZilSigner();
    contract = await hre.deployScillaContractWithSigner("BlockNumber", signer);
  });

  it("Deploy BlockNumber contract @block-1", async () => {
    expect(contract.address).to.be.properAddress;
  });

  it("Call BlockNumber contract -  EventBlockNumber @block-1", async () => {
    let result = (await hre.zilliqaSetup.zilliqa.blockchain.getNumTxBlocks()).result;
    const tx = await contract.EventBlockNumber();
    expect(tx).to.have.eventLogWithParams("BlockNumber", {value: result});
  });
});
