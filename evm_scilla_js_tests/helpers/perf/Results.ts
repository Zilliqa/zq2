import {Block} from "@ethersproject/providers";
import {Table} from "console-table-printer";

export interface TransferStatistics {
  count: number;
  latencies: number[];
}

export interface TransitionCallStatistics {
  count: number;
  transactionConfirmedLatencies: number[];
  receiptReceivedLatencies: number[];
  failedCalls: number;
}

export interface ReadStatistics {
  count: number;
  latencies: number[];
}

export interface PerfStatistics {
  readZilBalances: ReadStatistics;
  readEvmBalances: ReadStatistics;

  evmTransfers: TransferStatistics;
  zilTransfers: TransferStatistics;

  evmFunctionCalls: TransitionCallStatistics;
  scillaTransitionCalls: TransitionCallStatistics;
}

export function createEmptyPerfStatistics(): PerfStatistics {
  return {
    readZilBalances: {
      count: 0,
      latencies: []
    },
    readEvmBalances: {
      count: 0,
      latencies: []
    },
    evmTransfers: {
      count: 0,
      latencies: []
    },
    zilTransfers: {
      count: 0,
      latencies: []
    },
    evmFunctionCalls: {
      count: 0,
      transactionConfirmedLatencies: [],
      receiptReceivedLatencies: [],
      failedCalls: 0
    },
    scillaTransitionCalls: {
      count: 0,
      transactionConfirmedLatencies: [],
      receiptReceivedLatencies: [],
      failedCalls: 0
    }
  };
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

  if (stats.readZilBalances.count > 0) {
    table.addRow({
      Name: "Zil Balance Read",
      Count: stats.readZilBalances.count,
      Latency: calculateAverageLatency(stats.readZilBalances.latencies)
    });
  }

  if (stats.readEvmBalances.count > 0) {
    table.addRow({
      Name: "Evm Balance Read",
      Count: stats.readEvmBalances.count,
      Latency: calculateAverageLatency(stats.readEvmBalances.latencies)
    });
  }

  if (stats.zilTransfers.count > 0) {
    table.addRow({
      Name: "Simple Zil transfer",
      Count: stats.zilTransfers.count,
      Latency: calculateAverageLatency(stats.zilTransfers.latencies)
    });
  }
  if (stats.scillaTransitionCalls.count > 0) {
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

  if (stats.evmFunctionCalls.count > 0) {
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
