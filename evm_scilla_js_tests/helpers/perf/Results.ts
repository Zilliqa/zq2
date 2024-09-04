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

export class PerfStatistics {
  updateReadZilBalanceStats(stats: ReadStatistics) {
    this.readZilBalances = this.updateReadStatistics(stats, this.readZilBalances);
  }

  updateReadEvmBalanceStats(stats: ReadStatistics) {
    this.readEvmBalances = this.updateReadStatistics(stats, this.readEvmBalances);
  }

  updateEvmTransferStats(stats: TransferStatistics) {
    this.evmTransfers = this.updateTransferStatistics(stats, this.evmTransfers);
  }

  updateScillaTransitionCallStats(stats: TransitionCallStatistics) {
    this.scillaTransitionCalls = this.updateTransitionCallStatistics(stats, this.scillaTransitionCalls);
  }

  updateEvmFunctionCallStats(stats: TransitionCallStatistics) {
    this.evmFunctionCalls = this.updateTransitionCallStatistics(stats, this.evmFunctionCalls);
  }

  updateZilTransferStats(stats: TransferStatistics) {
    this.zilTransfers = this.updateTransferStatistics(stats, this.zilTransfers);
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

  private updateTransferStatistics(incoming: TransferStatistics, current?: TransferStatistics): TransferStatistics {
    if (current) {
      return {
        count: incoming.count + current.count,
        latencies: [...incoming.latencies, ...current.latencies]
      };
    }

    return incoming;
  }

  private updateTransitionCallStatistics(
    incoming: TransitionCallStatistics,
    current?: TransitionCallStatistics
  ): TransitionCallStatistics {
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

  evmTransfers?: TransferStatistics;
  zilTransfers?: TransferStatistics;

  evmFunctionCalls?: TransitionCallStatistics;
  scillaTransitionCalls?: TransitionCallStatistics;
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
      Latency: calculateAverageLatency(stats.zilTransfers.latencies)
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
