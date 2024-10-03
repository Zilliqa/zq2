import {expect} from "chai";
import hre from "hardhat";
import {Contract} from "ethers";
import {ethers} from "hardhat";

describe("Transaction Properties", function () {
  let contract: Contract;
  before(async function () {
    contract = await hre.deployContract("BlockAndTransactionProperties");
  });

  it("Should be deployed successfully @block-1", async function () {
    expect(contract.address).to.be.properAddress;
  });

  it("Should return the owner address when getOrigin function is called @block-1", async function () {
    const owner = contract.signer;
    expect(await contract.getTxOrigin()).to.be.eq(await owner.getAddress());
  });

  it("should return the correct msg sender", async function () {
    const [_owner, sender] = await ethers.getSigners();
    const contractMsgSender = await contract.connect(sender).getMsgSender();

    expect(contractMsgSender).to.equal(sender.address);
  });

  it("should return the correct msg sig", async function () {
    const contractMsgSig = await contract.getMsgSig();
    const expectedMsgSig = contract.interface.getSighash("getMsgSig()");

    expect(contractMsgSig).to.equal(expectedMsgSig);
  });

  xit("should return the correct msg value", async function () {
    const sendValue = ethers.utils.parseEther("0.001");
    await contract.getMsgValue({value: sendValue});

    expect(await contract.receivedValue()).to.equal(sendValue);
  });

  xit("should return the correct tx gas price", async function () {
    const contractTxGasPrice = await contract.getTxGasPrice();
    const currentGasPrice = await ethers.provider.getGasPrice();

    expect(contractTxGasPrice).to.equal(currentGasPrice);
  });
});
