# Title

eth_getBlockTransactionCountByHash

# Keywords

get,eth,block,transaction,count,hash

# Description

Returns a hex string representing the number of transactions in a block from a block matching the given block hash.

## Parameters

{{ macro_blockhash }}

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getBlockTransactionCountByHash",
    "params": [ "0x4f8547a34d79cafc135cf7c88e994321cd696ab54f00ab0fc8ecf209bf285bb4" ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x1","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description            |
|-----------|--------|----------|------------------------|
| `id`      | string | Required | `"1"`                  |
| `jsonrpc` | string | Required | `"2.0"`                |
| `method`  | string | Required | `"eth_getBlockByHash"` |
| `params`  | array  | Required | `[ block_hash ]` (*)   |


(*) Note that, although the Ethereum API docs claim that the block hash parameter is optional, it is mandatory in at least erigon and geth, and also in zq2.
