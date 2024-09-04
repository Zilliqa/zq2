import {Block} from "@ethersproject/providers";
import {Table} from "console-table-printer";

export interface TransferStatistics {
  totalTransfers: number;
  latencies: number[];
}

export interface TransitionCallStatistics {
  totalCalls: number;
  transactionConfirmedLatencies: number[];
  ReceiptReceivedLatencies: number[];
}

export interface ReadStatistics {
  totalCalls: number;
  latencies: number[];
}

export interface PerfStatistics {
  readZilBalances: ReadStatistics;
  readEvmBalances: ReadStatistics;

  evmTransfers: TransferStatistics;
  zilTransfers: TransferStatistics;

  evmFunctionCalls: TransitionCallStatistics;
  scillaFunctionCalls: TransitionCallStatistics;
}

export function createEmptyPerfStatistics(): PerfStatistics {
  return {
    readZilBalances: {
      totalCalls: 0,
      latencies: []
    },
    readEvmBalances: {
      totalCalls: 0,
      latencies: []
    },
    evmTransfers: {
      totalTransfers: 0,
      latencies: []
    },
    zilTransfers: {
      totalTransfers: 0,
      latencies: []
    },
    evmFunctionCalls: {
      totalCalls: 0,
      transactionConfirmedLatencies: [],
      ReceiptReceivedLatencies: []
    },
    scillaFunctionCalls: {
      totalCalls: 0,
      transactionConfirmedLatencies: [],
      ReceiptReceivedLatencies: []
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

  table.addRows([
    {
      Name: "Zil Balance Read",
      Count: stats.readZilBalances.totalCalls,
      Latency: calculateAverageLatency(stats.readZilBalances.latencies, stats.readZilBalances.totalCalls)
    },
    {
      Name: "Evm Balance Read",
      Count: stats.readEvmBalances.totalCalls,
      Latency: calculateAverageLatency(stats.readEvmBalances.latencies, stats.readEvmBalances.totalCalls)
    },
    {
      Name: "Simple Zil transfers",
      Count: stats.zilTransfers.totalTransfers,
      Latency: calculateAverageLatency(stats.zilTransfers.latencies, stats.zilTransfers.totalTransfers)
    }
  ]);

  table.printTable();
};

function calculateAverageLatency(latencies: number[], count: number): number {
  return latencies.reduce((accumulator, currentValue) => accumulator + currentValue, 0) / count;
}
