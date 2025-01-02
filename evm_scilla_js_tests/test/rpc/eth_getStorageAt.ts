import sendJsonRpcRequest from "../../helpers/JsonRpcHelper";
import {assert} from "chai";
import hre, {ethers} from "hardhat";
import logDebug from "../../helpers/DebugHelper";
import {Contract} from "ethers";

const METHOD = "eth_getStorageAt";

describe(`Calling ${METHOD} #parallel`, function () {
  let contract: Contract;
  before(async function () {
    const factory = await hre.ethers.getContractFactory("Storage");
    contract = await factory.deploy();
    await contract.deployed();
  });

  it("should return proper storage value when the defaultBlock is 'latest' for storage position 0 at address of contract @block-1", async function () {
    await sendJsonRpcRequest(METHOD, 1, [contract.address, "0x0", "latest"], (result, status) => {
      logDebug("Result:", result);
      assert.equal(status, 200, "has status code");
      assert.property(result, "result", result.error ? result.error.message : "error");
      assert.isString(result.result, "is string");
      assert.match(result.result, /^0x/, "should be HEX starting with 0x");

      assert.equal(parseInt(result.result, 16), 1024);
    });
  });

  it("should return proper storage value when a value from a map is requested @block-1", async function () {
    const MAPPING_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000001";

    // KEY that we want to read in the mapping
    const KEY = "0x0000000000000000000000000000000000000000000000000000000000000010";

    // Compute the actual storage slot of the value associated with the key
    const paddedKey = ethers.utils.hexZeroPad(KEY, 32);
    const paddedMappingSlot = ethers.utils.hexZeroPad(MAPPING_SLOT, 32);
    const balanceSlot = ethers.utils.keccak256(ethers.utils.concat([paddedKey, paddedMappingSlot]));

    await sendJsonRpcRequest(METHOD, 1, [contract.address, balanceSlot, "latest"], (result, status) => {
      logDebug("Result:", result);
      assert.equal(status, 200, "has status code");
      assert.property(result, "result", result.error ? result.error.message : "error");
      assert.isString(result.result, "is string");
      assert.match(result.result, /^0x/, "should be HEX starting with 0x");

      assert.equal(parseInt(result.result, 16), 2048);
    });
  });

  xit("should return proper storage value when the defaultBlock is '0x0' for storage position 0 at address of contract @block-1", async function () {
    await sendJsonRpcRequest(METHOD, 1, [contract.address, "0x0", "0x0"], (result, status) => {
      logDebug("Result:", result);
      assert.equal(status, 200, "has status code");
      assert.property(result, "result", result.error ? result.error.message : "error");
      assert.isString(result.result, "is string");
      assert.match(result.result, /^0x/, "should be HEX starting with 0x");

      assert.equal(parseInt(result.result, 16), 1024);
    });
  });

  it("should return an error when no parameter is passed @block-1", async function () {
    await sendJsonRpcRequest(METHOD, 1, [], (result, status) => {
      assert.equal(status, 200, "has status code");
      assert.property(result, "error");
      assert.equal(result.error.code, -32602);
    });
  });
});
