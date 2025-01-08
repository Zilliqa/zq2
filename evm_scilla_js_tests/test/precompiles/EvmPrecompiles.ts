import {expect} from "chai";
import hre from "hardhat";
import {ethers} from "hardhat";
import {Contract} from "ethers";

describe("Precompile tests with ethers.js #parallel", function () {
  let contract: Contract;
  before(async function () {
    const factory = await hre.ethers.getContractFactory("Precompiles");
    contract = await factory.deploy();
    await contract.deployed();
  });

  it("should return signer address when recover function is used @block-1", async function () {
    const msg = ethers.utils.toUtf8Bytes("SomeMessage");
    const docHash = ethers.utils.keccak256(msg);
    const account = ethers.Wallet.createRandom();
    const accountAddress = account.address;
    const signature = await account.signMessage(ethers.utils.arrayify(docHash));

    // Split the signature into r, s, and v
    const sig = ethers.utils.splitSignature(signature);

    const result = await contract.testRecovery(docHash, sig.v, sig.r, sig.s, {gasLimit: 7500000});

    expect(result).to.be.eq(accountAddress);
  });

  it("should return input value when identity function is used @block-1 [@transactional]", async function () {
    const msg = ethers.utils.toUtf8Bytes("SomeMessage");
    const hash = ethers.utils.keccak256(msg);

    const sendResult = await contract.testIdentity(hash);
    const receipt = await sendResult.wait();
    expect(sendResult).to.be.not.null;
    const readValue = await contract.idStored();
    expect(readValue).to.be.eq(hash);
  });

  it("should return correct hash when SHA2-256 function is used @block-1", async function () {
    const msg = "Hello World!";
    const expectedHash = "0x7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069";

    const readValue = await contract.testSHA256(msg);
    expect(readValue).to.be.eq(expectedHash);
  });

  it("should return correct hash when Ripemd160 function is used @block-1", async function () {
    const msg = "Hello World!";
    const expectedHash = "0x8476ee4631b9b30ac2754b0ee0c47e161d3f724c";

    const readValue = await contract.testRipemd160(msg);
    expect(readValue).to.be.eq(expectedHash);
  });

  xit("should return correct result when modexp function is used @block-1 [@transactional]", async function () {
    const base = 8;
    const exponent = 9;
    const modulus = 10;
    const expectedResult = 8;

    const [signer] = await hre.ethers.getSigners();
    const sendResult = await contract.testModexp(base, exponent, modulus, {from: signer.address});

    expect(sendResult).to.be.not.null;

    const readValue = await contract.modExpResult();
    expect(ethers.BigNumber.from(readValue)).to.be.eq(ethers.BigNumber.from(expectedResult));
  });

  it("should return correct result when ecAdd function is used @block-1", async function () {
    const tx = await contract.testEcAdd(1, 2, 1, 2);
    await tx.wait();

    const result = await Promise.all([contract.ecAddResult(0), contract.ecAddResult(1)]);
    expect(ethers.BigNumber.from(result[0])).to.be.eq(
      ethers.BigNumber.from("0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3")
    );
    expect(ethers.BigNumber.from(result[1])).to.be.eq(
      ethers.BigNumber.from("0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4")
    );
  });

  it("should return correct result when ecMul function is used @block-1", async function () {
    const tx = await contract.testEcMul(1, 2, 2);
    await tx.wait();

    const result = await Promise.all([contract.ecMulResult(0), contract.ecMulResult(1)]);
    expect(ethers.BigNumber.from(result[0])).to.be.eq(
      ethers.BigNumber.from("0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3")
    );
    expect(ethers.BigNumber.from(result[1])).to.be.eq(
      ethers.BigNumber.from("0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4")
    );
  });

  it("should return correct result when ecPairing function is used @block-1", async function () {
    const input = [
      "0x2cf44499d5d27bb186308b7af7af02ac5bc9eeb6a3d147c186b21fb1b76e18da",
      "0x2c0f001f52110ccfe69108924926e45f0b0c868df0e7bde1fe16d3242dc715f6",
      "0x1fb19bb476f6b9e44e2a32234da8212f61cd63919354bc06aef31e3cfaff3ebc",
      "0x22606845ff186793914e03e21df544c34ffe2f2f3504de8a79d9159eca2d98d9",
      "0x2bd368e28381e8eccb5fa81fc26cf3f048eea9abfdd85d7ed3ab3698d63e4f90",
      "0x2fe02e47887507adf0ff1743cbac6ba291e66f59be6bd763950bb16041a0a85e",
      "0x0000000000000000000000000000000000000000000000000000000000000001",
      "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45",
      "0x1971ff0471b09fa93caaf13cbf443c1aede09cc4328f5a62aad45f40ec133eb4",
      "0x091058a3141822985733cbdddfed0fd8d6c104e9e9eff40bf5abfef9ab163bc7",
      "0x2a23af9a5ce2ba2796c1f4e453a370eb0af8c212d9dc9acd8fc02c2e907baea2",
      "0x23a8eb0b0996252cb548a4487da97b02422ebc0e834613f954de6c7e0afdc1fc"
    ].map((n) => ethers.BigNumber.from(n));
    const tx = await contract.testEcPairing(input);
    await tx.wait();
    const result = await contract.pairingResult();
    expect(ethers.BigNumber.from(result)).to.be.eq(1);
  });

  it("should return correct result when blake2 function is used @block-1", async function () {
    const ROUNDS = 12;
    const H = [
      "0x48c9bdf267e6096a3ba7ca8485ae67bb2bf894fe72f36e3cf1361d5f3af54fa5",
      "0xd182e6ad7f520e511f6c3e2b8c68059b6bbd41fbabd9831f79217e1319cde05b"
    ];
    const M = [
      "0x6162630000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000",
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    ];
    const T = ["0x0300000000000000", "0x0000000000000000"];
    const F = true;

    const EXPECTED = [
      "0xba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1",
      "0x7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    ];

    const tx = await contract.testBlake2(ROUNDS, H, M, T, F);
    await tx.wait();

    const result = await Promise.all([contract.blake2Result(0), contract.blake2Result(1)]);
    expect(result[0]).to.be.eq(EXPECTED[0]);
    expect(result[1]).to.be.eq(EXPECTED[1]);
  });
});
