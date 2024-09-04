import {BN, Transaction, Zilliqa, bytes, getAddressFromPrivateKey, units} from "@zilliqa-js/zilliqa";
import {subtask, task} from "hardhat/config";
import Long from "long";
import fs from "fs";
import path from "path";
import {
  Account,
  CallContractConfig,
  createAndFundAccounts,
  fundAccount,
  generateAccount,
  getContractAbi,
  getNonce,
  ReadBalanceConfig,
  ScenarioType,
  TransferConfig,
  TransitionType
} from "../helpers/perf";

import {perfConfig} from "./Perf.config";
import {HardhatRuntimeEnvironment} from "hardhat/types";
import {AddedAccount, TransactionReceipt} from "web3-core";
import {Table} from "console-table-printer";
import {Block} from "@ethersproject/providers";

let web3Account: AddedAccount;

task("perf", "A task to get balance of a private key").setAction(async (taskArgs, hre) => {
  let zilliqa = new Zilliqa(hre.getNetworkUrl());
  web3Account = hre.web3.eth.accounts.wallet.add(perfConfig.sourceOfFunds);

  const provider = new hre.ethers.providers.WebSocketProvider(hre.getWebsocketUrl());
  const blocks: Block[] = [];
  provider.on("block", (blockNumber) => {
    provider.getBlock(blockNumber).then((block) => {
      blocks.push(block);
    });
  });

  zilliqa.wallet.addByPrivateKey(perfConfig.sourceOfFunds);

  const testData: TestData = await hre.run("perf:init-test-data", {zilliqa});

  for (const scenario of perfConfig.scenarios) {
    switch (scenario.type) {
      case ScenarioType.Transfer: {
        const transferConfig = scenario.config as TransferConfig;
        await hre.run("perf:transfer", {zilliqa, testData, transferConfig});
        break;
      }
      case ScenarioType.ReadBalance: {
        const readBalanceConfig = scenario.config as ReadBalanceConfig;
        await hre.run("perf:read-balance", {zilliqa, testData, readBalanceConfig});
        break;
      }
      case ScenarioType.CallContract: {
        const callContractConfig = scenario.config as CallContractConfig;
        await hre.run("perf:call-contract", {zilliqa, testData, callContractConfig, hre});
        break;
      }
      default:
        console.error(`${scenario.type} is not implemented yet`);
    }
  }

  printBlocksInfo(blocks);
});

function printBlocksInfo(blocks: Block[]) {
  const table = new Table();
  blocks
    .sort((a, b) => a.number - b.number)
    .map((block, index, blocks) => {
      return {
        number: block.number,
        gasUsed: block.gasUsed,
        numTransactions: block.transactions.length,
        timestamp: block.timestamp,
        timestampDelta: index > 0 ? block.timestamp - blocks[index - 1].timestamp : 0
      };
    })
    .forEach(({number, numTransactions, gasUsed, timestamp, timestampDelta}) => {
      table.addRow({
        "Block Number": number,
        "Number of transactions": numTransactions,
        "Gas Used": gasUsed,
        Timestamp: timestamp,
        "Timestamp Delta": timestampDelta
      });
    });

  table.printTable();
}

subtask("perf:init-test-data", "Create or load test-data").setAction(
  async ({zilliqa, numberOfAccounts}): Promise<TestData> => {
    const filePath = path.join(__dirname, "test-data.json");

    if (fs.existsSync(filePath) && fs.statSync(filePath).size > 0) {
      console.log("Loading test-data.json...");
      const data = fs.readFileSync(filePath, "utf8");
      return JSON.parse(data);
    }

    console.log("test-data.json is empty, creating a new one...");
    const accounts = await createAndFundAccounts(zilliqa, numberOfAccounts);

    // Save the new test data to the file
    fs.writeFileSync(filePath, JSON.stringify({accounts}, null, 2), "utf8");

    return {accounts};
  }
);

interface TestData {
  accounts: Account[];
}

subtask("perf:read-balance", "Read balance perf").setAction(
  async ({
    zilliqa,
    testData,
    readBalanceConfig
  }: {
    zilliqa: Zilliqa;
    testData: TestData;
    readBalanceConfig: ReadBalanceConfig;
  }) => {
    const iterations = readBalanceConfig.iterations;
    let totalLatency = 0;
    for (let i = 0; i < iterations; i++) {
      const start = Date.now();
      await zilliqa.blockchain.getBalance(testData.accounts[i].zilAddress);
      const end = Date.now();
      const latency = end - start;
      totalLatency += latency;
    }

    const averageLatency = totalLatency / iterations;
    console.log(`Average read balance latency over ${iterations} iterations: ${averageLatency} ms`);
  }
);

subtask("perf:transfer", "Transfer perf").setAction(
  async ({
    zilliqa,
    testData,
    transferConfig
  }: {
    zilliqa: Zilliqa;
    testData: TestData;
    transferConfig: TransferConfig;
  }) => {
    const iterations = transferConfig.iterations;
    let totalLatency = 0;

    let nonce = await getNonce(zilliqa, getAddressFromPrivateKey(perfConfig.sourceOfFunds));
    const promises = Array.from({length: iterations}, async (_, i) => {
      const account = generateAccount();
      const start = Date.now();
      await fundAccount(zilliqa, account.zilAddress, units.toQa("0.001", units.Units.Zil), (nonce += 1));
      const end = Date.now();
      const latency = end - start;
      totalLatency += latency;
    });

    await Promise.all(promises);

    const averageLatency = totalLatency / iterations;
    const table = new Table({title: "Transfer results"});
    table.addRows([
      {name: "Total Transfers", value: promises.length},
      {name: "Average Latency (ms)", value: averageLatency}
    ]);

    table.printTable();
  }
);

interface TransitionCallResult {
  latency: number;
  receiptLatency: number;
  success: boolean;
}

async function waitForReceipt(tx: Transaction) {
  let receipt = tx.getReceipt();
  while (!receipt) {
    await new Promise((resolve) => setTimeout(resolve, 1000)); // Wait for 1 second
    receipt = tx.getReceipt();
  }
  return receipt;
}

subtask("perf:call-contract", "call contarct perf").setAction(
  async ({
    zilliqa,
    testData,
    callContractConfig,
    hre
  }: {
    zilliqa: Zilliqa;
    testData: TestData;
    callContractConfig: CallContractConfig;
    hre: HardhatRuntimeEnvironment;
  }) => {
    let nonce = await getNonce(zilliqa, getAddressFromPrivateKey(perfConfig.sourceOfFunds));
    let promises: Promise<TransitionCallResult>[] = [];
    for (const callContract of callContractConfig.calls) {
      const contract = zilliqa.contracts.at(callContract.address);

      callContract.transitions.forEach((transition) => {
        if (callContract.type === TransitionType.Zil) {
          promises.push(
            ...Array.from({length: transition.iterations}, async (_, i): Promise<TransitionCallResult> => {
              let start = Date.now();
              let latency = 0;
              let receiptLatency = 0;
              const tx = await contract.call(transition.name, transition.args, {
                version: bytes.pack(1, 1),
                amount: new BN(0),
                gasPrice: units.toQa("2000", units.Units.Li),
                gasLimit: Long.fromNumber(8000),
                nonce: (nonce += 1)
              });
              latency = Date.now() - start;
              const receipt = await waitForReceipt(tx);
              receiptLatency = Date.now() - start;
              return {
                latency,
                receiptLatency,
                success: receipt.success
              };
            })
          );
        } else if (callContract.type === TransitionType.Evm) {
          const abi = getContractAbi(callContract.name);
          if (abi === undefined) {
            console.error(`Failed to get the contract ABI for ${callContract.name}`);
            return;
          }
          const contract = new hre.web3.eth.Contract(abi, callContract.address, {
            from: web3Account.address
          });
          const method = contract.methods[transition.name];
          if (method === undefined) {
            console.error(`Failed to get the method ${transition.name}`);
            return;
          }
          promises.push(
            ...Array.from({length: transition.iterations}, async (_, i) => {
              let start = Date.now();
              let success = false;
              let latency = 0;
              let receiptLatency = 0;
              let tx = await method(...transition.args)
                .send({gasLimit: 1000000})
                .on("transactionHash", function () {
                  latency = Date.now() - start;
                })
                .on("receipt", function (receipt: TransactionReceipt) {
                  success = receipt.status;
                  receiptLatency = Date.now() - start;
                })
                .on("error", function () {
                  success = false;
                });
              return {
                latency,
                receiptLatency,
                success
              };
            })
          );
        }
      });
    }
    const results = await Promise.all(promises);
    const latencies = results.reduce((accumulator, currentValue) => accumulator + currentValue.latency, 0);
    const receiptLtencies = results.reduce((accumulator, currentValue) => accumulator + currentValue.receiptLatency, 0);
    const rejectedCount = results.reduce(
      (accumulator, currentValue) => accumulator + (currentValue.success ? 0 : 1),
      0
    );

    const averageLatency = latencies / promises.length;
    const averageReceiptLatency = receiptLtencies / promises.length;
    const rejectRate = rejectedCount / promises.length;

    const table = new Table();
    table.addRows([
      {name: "Total Calls", value: promises.length},
      {name: "Average Latency (ms)", value: averageLatency},
      {name: "Average Receipt Latency (ms)", value: averageReceiptLatency}
    ]);
    table.addRow({name: "Reject Rate", value: rejectRate}, {color: rejectRate === 0 ? "green" : "yellow"});

    table.printTable();
  }
);
