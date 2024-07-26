# Title

eth_getTransactionReceipt

# Keywords

get,transaction,receipt,eth

# Description

Retrieve a transaction receipt, or return `null`.

## Parameters

A transaction hash.

## Returns

{{ macro_transaction_receipt }}

{{ macro_logobject }}

{{ macro_logs_bloom }}

# Curl


```sh
curl -d '{
   "id": "1",
   "jsonrpc": "2.0",
   "method": "eth_getTransactionReceipt",
   "params": [ "0x11106d9da5ea70ac5ed3a2f2f3a7fba83557baa94b272a8f0314a471a8c0289c" 
]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```


# Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "transactionHash": "0x11106d9da5ea70ac5ed3a2f2f3a7fba83557baa94b272a8f0314a471a8c0289c",
    "transactionIndex": "0x0",
    "blockHash": "0x4623183dee0739450abb8077a33a02cae77aece4f49c6ec49a4462eae1efbf3f",
    "blockNumber": "0xe6b",
    "from": "0xcb57ec3f064a16cadb36c7c712f4c9fa62b77415",
    "to": "0xbca0f6f4cbfe8ac37096b674de8f96c701c43f7c",
    "cumulativeGasUsed": "0x849a",
    "effectiveGasPrice": "0x454b7a4e100",
    "gasUsed": "0x849a",
    "contractAddress": null,
    "logs": [
      {
        "removed": false,
        "logIndex": "0x0",
        "transactionIndex": "0x0",
        "transactionHash": "0x11106d9da5ea70ac5ed3a2f2f3a7fba83557baa94b272a8f0314a471a8c0289c",
        "blockHash": "0x4623183dee0739450abb8077a33a02cae77aece4f49c6ec49a4462eae1efbf3f",
        "blockNumber": "0xe6b",
        "address": "0xbca0f6f4cbfe8ac37096b674de8f96c701c43f7c",
        "data": "0x00000000000000000000000000000000000000000000000000000000000003e8",
        "topics": [
          "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
          "0x000000000000000000000000cb57ec3f064a16cadb36c7c712f4c9fa62b77415",
          "0x0000000000000000000000000000000000000000000000000000000000000000"
        ]
      }
    ],
    "logsBloom": "0x00000000000000000000008000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000020000000000020000000000000000000800000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400000000000000000000000001000002000000000000000000000000100000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000",
    "type": "0x0",
    "status": "0x1"
  },
  "id": "1"
}
```

# Arguments

| Parameter | Type   | Required | Description            |
|-----------|--------|----------|------------------------|
| `id`      | string | Required | `"1"`                  |
| `jsonrpc` | string | Required | `"2.0"`                |
| `method`  | string | Required | `"eth_getBlockByHash"` |
| `params`  | array  | Required | `[ txn_hash ]`         |

