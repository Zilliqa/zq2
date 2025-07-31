# Title

eth_feeHistory

# Keywords

eth,fee,history

# Description

Returns historical gas fee information, including base fees and priority fees, for a range of blocks. This method is useful for estimating appropriate gas fees for transactions.

## Parameters

### blockCount
Number of blocks in the requested range. Between 1 and 1024 blocks can be requested in a single query.

### Newest Block
Highest number block of the requested range.

### Reward Percentiles (Optional)
A monotonically increasing list of percentile values to sample from each block's effective priority fees per gas in ascending order, weighted by gas used.

## Return values
An object with this properties:

* `oldestBlock` - Lowest number block of the returned range.
* `baseFeePerGas` - An array of block base fees per gas. This includes the next block after the newest of the returned range, because this value can be derived from the newest block. Zeroes are returned for pre-EIP-1559 blocks.
* `gasUsedRatio` - An array of block gas used ratios. These are calculated as the ratio of gasUsed and gasLimit.
* `reward` - (Optional) An array of effective priority fees per gas data points from a single block. All zeroes are returned if the block is empty.
* `baseFeePerBlobGas` - An array of base fees per blob gas for blocks. This includes the next block following the newest in the returned range, as this value can be derived from the latest block. For blocks before EIP-4844, zeroes are returned.
* `blobGasUsedRatio` - An array showing the ratios of blob gas used in blocks. These ratios are calculated by dividing blobGasUsed by the maximum blob gas per block.

# Curl

```shell
curl -d '{
  "id": "1",
  "jsonrpc": "2.0",
  "method": "eth_feeHistory",
  "params": [
    "5", "0x10d4f", [25, 50, 75]
]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "oldestBlock": "0x10d4f",
    "reward": [
      ["0x8c", "0x9c", "0x6d"],
      ["0x78", "0x8b", "0x5a"],
      ["0x70", "0x86", "0x52"],
      ["0x6c", "0x85", "0x51"],
      ["0x67", "0x82", "0x4d"]
    ],
    "baseFeePerGas": [
      "0x7",
      "0xa",
      "0xd",
      "0xc",
      "0xf",
      "0xe"
    ],
    "gasUsedRatio": [
      0.887174,
      0.953874,
      0.935209,
      0.909315,
      0.802646
    ]
  },
  "id": "1"
}
```

# Arguments

| Parameter | Type   | Required | Description                          |
|-----------|--------|----------|--------------------------------------|
| `id`      | string | Required | `"1"`                                |
| `jsonrpc` | string | Required | `"2.0"`                              |
| `method`  | string | Required | `"eth_feeHistory"`                   |
| `params`  | array  | Required | `[blockCount, newestBlock, rewardPercentiles]` |
