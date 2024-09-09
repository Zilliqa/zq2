import {Block} from "@ethersproject/providers";
import {Table} from "console-table-printer";
import {EvmOrZil, ScenarioType} from "./Config";

export interface TransactionStatistics {
  count: number;
  transactionConfirmedLatencies: number[];
  receiptReceivedLatencies: number[];
  failedCalls: number;
}

export interface ReadStatistics {
  count: number;
  latencies: number[];
}

export interface TransactionCallResult {
  latency: number;
  receiptLatency: number;
  success: boolean;
  type: EvmOrZil;
  scenario: ScenarioType;
}

export interface ReadCallResult {
  latency: number;
  type: EvmOrZil;
  scenario: ScenarioType;
}

export class PerfStatistics {
  constructor(reads: ReadCallResult[], transactions: TransactionCallResult[]) {
    const readBalances = reads.filter((read) => read.scenario === ScenarioType.ReadBalance);
    const zilReadBalances = readBalances.filter((read) => read.type === EvmOrZil.Zil);
    if (zilReadBalances.length > 0) {
      this.readZilBalances = {
        count: zilReadBalances.length,
        latencies: zilReadBalances.map((read) => read.latency)
      };
    }

    const evmReadBalances = readBalances.filter((read) => read.type === EvmOrZil.Evm);

    if (evmReadBalances.length > 0) {
      this.readEvmBalances = {
        count: evmReadBalances.length,
        latencies: evmReadBalances.map((read) => read.latency)
      };
    }

    const simpleTransfers = transactions.filter((txn) => txn.scenario === ScenarioType.Transfer);
    const zilTransfers = simpleTransfers.filter((txn) => txn.type === EvmOrZil.Zil);
    if (zilTransfers.length > 0) {
      this.zilTransfers = {
        count: zilTransfers.length,
        transactionConfirmedLatencies: zilTransfers.map((txn) => txn.latency),
        receiptReceivedLatencies: zilTransfers.map((txn) => txn.receiptLatency),
        failedCalls: zilTransfers.filter((txn) => !txn.success).length
      };
    }

    const evmTransfers = simpleTransfers.filter((txn) => txn.type === EvmOrZil.Evm);

    if (evmTransfers.length > 0) {
      this.evmTransfers = {
        count: evmTransfers.length,
        transactionConfirmedLatencies: evmTransfers.map((txn) => txn.latency),
        receiptReceivedLatencies: evmTransfers.map((txn) => txn.receiptLatency),
        failedCalls: evmTransfers.filter((txn) => !txn.success).length
      };
    }

    const functionCalls = transactions.filter((txn) => txn.scenario === ScenarioType.CallContract);
    const scillaCalls = functionCalls.filter((txn) => txn.type === EvmOrZil.Zil);
    if (scillaCalls.length > 0) {
      this.scillaTransitionCalls = {
        count: scillaCalls.length,
        transactionConfirmedLatencies: scillaCalls.map((txn) => txn.latency),
        receiptReceivedLatencies: scillaCalls.map((txn) => txn.receiptLatency),
        failedCalls: scillaCalls.filter((txn) => !txn.success).length
      };
    }

    const evmCalls = functionCalls.filter((txn) => txn.type === EvmOrZil.Evm);
    if (evmCalls.length > 0) {
      this.evmFunctionCalls = {
        count: evmCalls.length,
        transactionConfirmedLatencies: evmCalls.map((txn) => txn.latency),
        receiptReceivedLatencies: evmCalls.map((txn) => txn.receiptLatency),
        failedCalls: evmCalls.filter((txn) => !txn.success).length
      };
    }
  }

  private updateReadStatistics(incoming: ReadStatistics, current?: ReadStatistics): ReadStatistics {
    if (current) {
      return {
        count: incoming.count + current.count,
        latencies: [...incoming.latencies, ...current.latencies]
      };
    }

    return incoming;
  }

  private updateTransactionStatistics(
    incoming: TransactionStatistics,
    current?: TransactionStatistics
  ): TransactionStatistics {
    if (current) {
      return {
        count: incoming.count + current.count,
        transactionConfirmedLatencies: [
          ...incoming.transactionConfirmedLatencies,
          ...current.transactionConfirmedLatencies
        ],
        receiptReceivedLatencies: [...incoming.receiptReceivedLatencies, ...current.receiptReceivedLatencies],
        failedCalls: incoming.failedCalls + current.failedCalls
      };
    }

    return incoming;
  }

  readZilBalances?: ReadStatistics;
  readEvmBalances?: ReadStatistics;

  evmTransfers?: TransactionStatistics;
  zilTransfers?: TransactionStatistics;

  evmFunctionCalls?: TransactionStatistics;
  scillaTransitionCalls?: TransactionStatistics;
}

export function printBlocksInfo(blocks: Block[]) {
  if (blocks.length === 0) {
    console.log("🫤  No block captured during this perf round.");
    return;
  }
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

export const printResults = (stats: PerfStatistics) => {
  const table = new Table();

  if (stats.readZilBalances) {
    table.addRow({
      Name: "Zil Balance Read",
      Count: stats.readZilBalances.count,
      Latency: calculateAverageLatency(stats.readZilBalances.latencies)
    });
  }

  if (stats.readEvmBalances) {
    table.addRow({
      Name: "Evm Balance Read",
      Count: stats.readEvmBalances.count,
      Latency: calculateAverageLatency(stats.readEvmBalances.latencies)
    });
  }

  if (stats.zilTransfers) {
    table.addRow({
      Name: "Simple Zil transfer",
      Count: stats.zilTransfers.count,
      "Confirm Latency": calculateAverageLatency(stats.zilTransfers.transactionConfirmedLatencies),
      "Receipt Latency": calculateAverageLatency(stats.zilTransfers.receiptReceivedLatencies),
      "Failed Calls": stats.zilTransfers.failedCalls,
      "Success Rate": (stats.zilTransfers.count - stats.zilTransfers.failedCalls) / stats.zilTransfers.count
    });
  }

  if (stats.evmTransfers) {
    table.addRow({
      Name: "Simple EVM transfer",
      Count: stats.evmTransfers.count,
      "Confirm Latency": calculateAverageLatency(stats.evmTransfers.transactionConfirmedLatencies),
      "Receipt Latency": calculateAverageLatency(stats.evmTransfers.receiptReceivedLatencies),
      "Failed Calls": stats.evmTransfers.failedCalls,
      "Success Rate": (stats.evmTransfers.count - stats.evmTransfers.failedCalls) / stats.evmTransfers.count
    });
  }

  if (stats.scillaTransitionCalls) {
    table.addRow({
      Name: "Scilla Transition Call",
      Count: stats.scillaTransitionCalls.count,
      "Confirm Latency": calculateAverageLatency(stats.scillaTransitionCalls.transactionConfirmedLatencies),
      "Receipt Latency": calculateAverageLatency(stats.scillaTransitionCalls.receiptReceivedLatencies),
      "Failed Calls": stats.scillaTransitionCalls.failedCalls,
      "Success Rate":
        (stats.scillaTransitionCalls.count - stats.scillaTransitionCalls.failedCalls) /
        stats.scillaTransitionCalls.count
    });
  }

  if (stats.evmFunctionCalls) {
    table.addRow({
      Name: "EVM Function Call",
      Count: stats.evmFunctionCalls.count,
      "Confirm Latency": calculateAverageLatency(stats.evmFunctionCalls.transactionConfirmedLatencies),
      "Receipt Latency": calculateAverageLatency(stats.evmFunctionCalls.receiptReceivedLatencies),
      "Failed Calls": stats.evmFunctionCalls.failedCalls,
      "Success Rate": (stats.evmFunctionCalls.count - stats.evmFunctionCalls.failedCalls) / stats.evmFunctionCalls.count
    });
  }

  table.printTable();
};

function calculateAverageLatency(latencies: number[]): number {
  return latencies.reduce((accumulator, currentValue) => accumulator + currentValue, 0) / latencies.length;
}
