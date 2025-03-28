import { expect } from "chai";
import hre from "hardhat";
import { ScillaContract } from "hardhat-scilla-plugin";
import { Account } from "@zilliqa-js/zilliqa";

describe("Scilla SimpleMap", function () {
  let contract: ScillaContract;
  let signer: Account;
  before(async function () {
    if (!hre.isZilliqaNetworkSelected() || !hre.isScillaTestingEnabled()) {
      this.skip();
    }

    contract = await hre.deployScillaContract2("SimpleMap");
  });

  it("Should be deployed successfully @block-1", async function () {
    expect(contract.address).to.be.properAddress;
  });

  it("Should return an empty map for `simple_map` if contract's state is fetched", async function () {
    const state = await contract.getState();

    expect(state.simple_map).to.be.an("object");
    expect(Object.keys(state.simple_map).length).to.equal(0);
  });

  it("Should return an empty map for `simple_map` if contract's sub state is fetched", async function () {
    const state = await contract.getSubState("simple_map");

    expect(state.simple_map).to.be.an("object");
    expect(Object.keys(state.simple_map).length).to.equal(0);
  });

  it("Should return a map with one entry for `simple_map` if contract's (sub)state is fetched after `AddToMap` transition is called", async function () {
    await contract.AddToMap(12, "value1");
    const state = await contract.getState();

    expect(state.simple_map).to.be.an("object");
    expect(Object.keys(state.simple_map).length).to.equal(1);
    expect(state.simple_map["12"]).to.equal("value1");

    const subState = await contract.getSubState("simple_map");
    expect(subState.simple_map).to.be.an("object");
    expect(Object.keys(subState.simple_map).length).to.equal(1);
    expect(subState.simple_map["12"]).to.equal("value1");

  });
});
