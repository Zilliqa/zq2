const {expect} = require("chai");
import {ScillaContract} from "hardhat-scilla-plugin";
import hre from "hardhat";
import {Account} from "@zilliqa-js/zilliqa";

describe("ChainId contract #parallel", () => {
  let contract: ScillaContract;

  before(async () => {
    contract = await hre.deployScillaContract2("ChainId");
  });

  it("Deploy chainId contract @block-1", async () => {
    expect(contract.address).to.be.properAddress;
  });

  it("Call chain id contract -  EventChainId @block-1", async () => {
    const tx = await contract.EventChainID();

    expect(tx).to.have.eventLogWithParams("ChainID", {value: hre.getZilliqaChainId()});
  });
});
