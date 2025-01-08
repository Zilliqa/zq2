import {expect} from "chai";
import hre, {ethers} from "hardhat";
import {Contract} from "ethers";
import {BigNumber} from "ethers";

describe("Contract destruction with ethers.js", function () {
  let amountPaid: BigNumber;
  before(function () {
    amountPaid = ethers.utils.parseUnits("3", "gwei");
  });

  describe("When a user method call", function () {
    let contract: Contract;
    before(async function () {
      const ContractFactory = await hre.ethers.getContractFactory("ParentContract");
      contract = await ContractFactory.deploy({value: amountPaid});
      await contract.deployed();
    });

    it("should be destructed and coins in the contract should be transferred to the address specified in the method [@transactional]", async function () {
      const paidValue = await contract.getPaidValue();
      expect(paidValue).to.be.eq(amountPaid);

      const destAccount = ethers.Wallet.createRandom().address;
      const prevBalance = await hre.ethers.provider.getBalance(destAccount);

      const tx = await contract.returnToSenderAndDestruct(destAccount);
      await tx.wait();

      const newBalance = await hre.ethers.provider.getBalance(destAccount);

      // Dest Account should have prevBalance + amountPaid
      expect(BigNumber.from(newBalance)).to.eq(BigNumber.from(prevBalance).add(amountPaid));
    });
  });

  describe("When a method call happens through another contract", function () {
    let contract: Contract;
    before(async function () {
      const ContractFactory = await hre.ethers.getContractFactory("ParentContract");
      contract = await ContractFactory.deploy({value: amountPaid});
      await contract.deployed();
    });

    it("Should be destructed and coins in the contract should be transferred to the address specified in the method [@transactional]", async function () {
      const tx = await contract.installChild(123, {gasLimit: 1000000});
      await tx.wait();

      const childAddress = await contract.childAddress();
      const ChildContractFactory = await hre.ethers.getContractFactory("ChildContract");
      const childContract = new ethers.Contract(childAddress, ChildContractFactory.interface, contract.signer);

      const prevBalance = await hre.ethers.provider.getBalance(contract.address);
      const returnTx = await childContract.returnToSender();
      await returnTx.wait();

      const newBalance = await hre.ethers.provider.getBalance(contract.address);

      // Parent contract should have prevBalance + amountPaid
      expect(BigNumber.from(newBalance)).to.eq(BigNumber.from(prevBalance).add(amountPaid));
    });
  });
});
