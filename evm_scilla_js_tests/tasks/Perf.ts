import {BN, Transaction, Zilliqa, bytes, getAddressFromPrivateKey, units} from "@zilliqa-js/zilliqa";
import {subtask, task} from "hardhat/config";
import Long from "long";
import fs from "fs";
import path from "path";
import {
  Account,
  CallContractConfig,
  createAndFundAccounts,
  EvmOrZil,
  fundAccount,
  generateAccount,
  getContractAbi,
  getNonce,
  PerfStatistics,
  printBlocksInfo,
  printResults,
  ReadBalanceConfig,
  ReadCallResult,
  ScenarioType,
  TransactionCallResult,
  TransferConfig
} from "../helpers/perf";

import {perfConfig} from "./Perf.config";
import {HardhatRuntimeEnvironment} from "hardhat/types";
import {AddedAccount, TransactionReceipt} from "web3-core";
import {Block} from "@ethersproject/providers";

let web3Account: AddedAccount;

task("perf", "Performance measurement task").setAction(async (taskArgs, hre) => {
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
    let readPromises: Promise<ReadCallResult>[] = [];
    let transactionPromises: Promise<TransactionCallResult>[] = [];
    console.log(`👽 Running ${scenario.name}...`);
    for (const step of scenario.steps) {
      switch (step.type) {
        case ScenarioType.Transfer: {
          const transferConfig = step.config as TransferConfig;
          transactionPromises.push(...(await generateSimpleTransferTransactions(zilliqa, hre, transferConfig)));
          break;
        }
        case ScenarioType.ReadBalance: {
          const readBalanceConfig = step.config as ReadBalanceConfig;
          readPromises.push(...generateBalanceReadRequests(zilliqa, hre, readBalanceConfig));
          break;
        }
        case ScenarioType.CallContract: {
          const callContractConfig = step.config as CallContractConfig;
          transactionPromises.push(...(await generateCallContractTransactions(zilliqa, hre, callContractConfig)));
          break;
        }
        default:
          console.error(`  ☹️ ${step.type} is not implemented yet`);
      }
    }

    const [reads, txns] = await Promise.all([Promise.all(readPromises), Promise.all(transactionPromises)]);
    const perfStatistics = new PerfStatistics(reads, txns);
    printResults(perfStatistics);
  }

  printBlocksInfo(blocks);
});

async function generateSimpleTransferTransactions(
  zilliqa: Zilliqa,
  hre: HardhatRuntimeEnvironment,
  transferConfig: TransferConfig
): Promise<Promise<TransactionCallResult>[]> {
  const {iterations} = transferConfig;

  let nonce = await getNonce(zilliqa, getAddressFromPrivateKey(perfConfig.sourceOfFunds));
  const promises = Array.from({length: iterations}, async (_, i): Promise<TransactionCallResult> => {
    const account = generateAccount();
    const start = Date.now();
    await fundAccount(zilliqa, account.zilAddress, units.toQa("0.001", units.Units.Zil), (nonce += 1));
    return {
      latency: Date.now() - start,
      receiptLatency: 0,
      success: true,
      type: transferConfig.type,
      scenario: ScenarioType.Transfer
    };
  });

  return promises;
}

function generateBalanceReadRequests(
  zilliqa: Zilliqa,
  hre: HardhatRuntimeEnvironment,
  readBalanceConfig: ReadBalanceConfig
): Promise<ReadCallResult>[] {
  const {iterations, type, accounts} = readBalanceConfig;

  if (type === EvmOrZil.Zil) {
    return Array.from({length: iterations}, async (_, i): Promise<ReadCallResult> => {
      const start = Date.now();
      await zilliqa.blockchain.getBalance(accounts[i % accounts.length]);
      const end = Date.now();
      return {
        latency: end - start,
        type: EvmOrZil.Zil,
        scenario: ScenarioType.ReadBalance
      };
    });
  } else {
    return Array.from({length: iterations}, async (_, i): Promise<ReadCallResult> => {
      const start = Date.now();
      hre.ethers.provider.getBalance(accounts[i % accounts.length]);
      const end = Date.now();
      return {
        latency: end - start,
        type: EvmOrZil.Evm,
        scenario: ScenarioType.ReadBalance
      };
    });
  }
}

async function generateCallContractTransactions(
  zilliqa: Zilliqa,
  hre: HardhatRuntimeEnvironment,
  callContractConfig: CallContractConfig
): Promise<Promise<TransactionCallResult>[]> {
  let nonce = await getNonce(zilliqa, getAddressFromPrivateKey(perfConfig.sourceOfFunds));
  let promises: Promise<TransactionCallResult>[] = [];
  for (const callContract of callContractConfig.calls) {
    const contract = zilliqa.contracts.at(callContract.address);

    callContract.transitions.forEach((transition) => {
      if (callContract.type === EvmOrZil.Zil) {
        promises.push(
          ...Array.from({length: transition.iterations}, async (_, i): Promise<TransactionCallResult> => {
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
              success: receipt.success,
              type: EvmOrZil.Zil,
              scenario: ScenarioType.CallContract
            };
          })
        );
      } else if (callContract.type === EvmOrZil.Evm) {
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
            await method(...transition.args)
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
              success,
              type: EvmOrZil.Evm,
              scenario: ScenarioType.CallContract
            };
          })
        );
      }
    });
  }

  return promises;
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

async function waitForReceipt(tx: Transaction) {
  let receipt = tx.getReceipt();
  while (!receipt) {
    await new Promise((resolve) => setTimeout(resolve, 1000)); // Wait for 1 second
    receipt = tx.getReceipt();
  }
  return receipt;
}
