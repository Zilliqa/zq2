import {Block} from "@ethersproject/providers";
import {Table} from "console-table-printer";

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

export class PerfStatistics {
  updateReadZilBalanceStats(stats: ReadStatistics) {
    this.readZilBalances = this.updateReadStatistics(stats, this.readZilBalances);
  }

  updateReadEvmBalanceStats(stats: ReadStatistics) {
    this.readEvmBalances = this.updateReadStatistics(stats, this.readEvmBalances);
  }

  updateEvmTransferStats(stats: TransactionStatistics) {
    this.evmTransfers = this.updateTransactionStatistics(stats, this.evmTransfers);
  }

  updateScillaTransitionCallStats(stats: TransactionStatistics) {
    this.scillaTransitionCalls = this.updateTransactionStatistics(stats, this.scillaTransitionCalls);
  }

  updateEvmFunctionCallStats(stats: TransactionStatistics) {
    this.evmFunctionCalls = this.updateTransactionStatistics(stats, this.evmFunctionCalls);
  }

  updateZilTransferStats(stats: TransactionStatistics) {
    this.zilTransfers = this.updateTransactionStatistics(stats, this.zilTransfers);
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
