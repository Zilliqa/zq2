import {ScillaContract} from "hardhat-scilla-plugin";
import {expect} from "chai";
import hre, {ethers} from "hardhat";
import {parallelizer} from "../../helpers";
import {BN, units, Zilliqa} from "@zilliqa-js/zilliqa";

describe("Move Zil #parallel", function () {
  const ZIL_AMOUNT = units.toQa(0.1, units.Units.Zil);
  let contract: ScillaContract;
  let to_be_funded_contract: ScillaContract;
  let zilliqa: Zilliqa;

  before(async function () {
    if (!hre.isZilliqaNetworkSelected() || !hre.isScillaTestingEnabled()) {
      this.skip();
    }

    zilliqa = new Zilliqa(hre.getNetworkUrl());

    if (hre.parallel) {
      [contract, to_be_funded_contract] = await Promise.all([
        hre.deployScillaContract2("SendZil"),
        hre.deployScillaContract2("SendZil")
      ]);
    } else {
      contract = await parallelizer.deployScillaContract("SendZil");
      to_be_funded_contract = await parallelizer.deployScillaContract("SendZil");
    }
  });

  it("Should be deployed successfully @block-1", async function () {
    expect(contract.address).to.be.properAddress;
    expect(to_be_funded_contract.address).to.be.properAddress;
  });

  it("Should have updated balance if accept is called @block-1", async function () {
    const tx = await contract.acceptZil({amount: new BN(ZIL_AMOUNT)});
    expect(tx).to.have.eventLogWithParams("currentBalance", {value: new BN(ZIL_AMOUNT).toString()});
  });

  it("Should have untouched balance if accept is NOT called", async function () {
    const tx = await contract.dontAcceptZil({amount: ZIL_AMOUNT});

    // Exactly equal to what is has from previous transition
    expect(tx).to.have.eventLogWithParams("currentBalance", {value: new BN(ZIL_AMOUNT).toString()});
  });

  it("Should be possible to fund a user", async function () {
    const account = ethers.Wallet.createRandom();
    await contract.fundUser(account.address, ZIL_AMOUNT);

    const balanceResponse = await zilliqa.blockchain.getBalance(account.address);
    const balance = Number.parseInt(balanceResponse.result.balance);
    expect(balance).to.be.eq(ZIL_AMOUNT);
  });

  it("Should be possible to fund a user with an AddFunds message", async function () {
    const account = ethers.Wallet.createRandom();
    const result = await contract.fundUserWithTag(account.address, ZIL_AMOUNT);
    const balanceResponse = await zilliqa.blockchain.getBalance(account.address);
    const balance = Number.parseInt(balanceResponse.result.balance);
    expect(balance).to.be.eq(ZIL_AMOUNT);
  });

  it("Should be possible to fund a contract", async function () {
    await contract.fundContract(to_be_funded_contract.address, ZIL_AMOUNT);

    let balanceResponse = await zilliqa.blockchain.getBalance(to_be_funded_contract.address!);
    let balance = Number.parseInt(balanceResponse.result.balance);
    expect(balance).to.be.eq(ZIL_AMOUNT);

    balanceResponse = await zilliqa.blockchain.getBalance(contract.address!);
    balance = Number.parseInt(balanceResponse.result.balance);
    expect(balance).to.be.eq(0);
  });

  it("Should be possible to call a contract transition through another contract", async function () {
    await contract.callOtherContract(to_be_funded_contract.address, "updateTestField", 1234);

    expect(await to_be_funded_contract.test_field()).to.be.eq(1234);
  });
});
