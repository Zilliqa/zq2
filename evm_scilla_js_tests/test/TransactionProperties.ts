import {expect} from "chai";
import hre from "hardhat";
import {BigNumber, Contract} from "ethers";
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

  it("should return the correct msg.sender", async function () {
    const [_owner, sender] = await ethers.getSigners();
    const contractMsgSender = await contract.connect(sender).getMsgSender();

    expect(contractMsgSender).to.equal(sender.address);
  });

  it("should return the correct msg.sig", async function () {
    const contractMsgSig = await contract.getMsgSig();
    const expectedMsgSig = contract.interface.getSighash("getMsgSig()");

    expect(contractMsgSig).to.equal(expectedMsgSig);
  });

  it("should return the correct msg.value and msg.data", async function () {
    const emittedData = contract.interface.getSighash("receiveEther");
    const sendValue = ethers.utils.parseEther("0.001");

    const [owner] = await ethers.getSigners();
    const tx = await contract.receiveEther({value: sendValue});
    await expect(tx).to.emit(contract, "Received").withArgs(owner.address, sendValue, emittedData);
  });

  it("should return the correct gasLeft", async function () {
    const tx = await contract.emitGasLeft();
    const receipt = await tx.wait();

    const event = receipt.events.find((event: any) => event.event === "GasLeft");
    const emittedGas = event.args.gas;

    expect(emittedGas).to.be.greaterThan(BigNumber.from(0));
  });

  it("should emit tx.gasprice correctly with overridden gas price", async function () {
    const customGasPrice = ethers.utils.parseUnits("5000", "gwei");
    const tx = await contract.emitGasPrice({gasPrice: customGasPrice});
    await expect(tx).to.emit(contract, "GasPrice").withArgs(customGasPrice);
  });
});
