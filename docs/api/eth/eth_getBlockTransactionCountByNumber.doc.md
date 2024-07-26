# Title

eth_getBlockTransactionCountByNumber

# Keywords

get,eth,block,transaction,count,number

# Description

Returns the number of transactions in a block specified by a block number, as a hex string.

## Parameters

{{ macro_blocknumber }}

## Result

A count as a hex string, or `null` if the block with this hash is not known to this node.

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getBlockTransactionCountByNumber",
    "params": [ "0x82" ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
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
| `params`  | array  | Required | `[ block_number ]` (*)   |


(*) Note that, although the Ethereum API docs claim that the block number parameter is optional, it is mandatory in at least erigon and geth, and also in zq2.
