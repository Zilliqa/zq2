# Title

eth_call

# Keywords

eth,call,contract,call

# Description

Given a transaction and a block number, executes a new message call immediately, without creating a transaction. The result is the result of the contract call.

## Parameters

{{ macro_transaction }}

{{ macro_blocknumber }}

# Curl

```sh
 curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_call",
    "params": [ {
        "from": "0xcb57ec3f064a16cadb36c7c712f4c9fa62b77415",
        "to": "0x421833De81427cEAEE3E69b090ED30a766f9D383",
        "gas": "0x100000",
        "gas_price": "0x1",
        "value": "0x0",
        "data": "0x85bb7d69" },  "latest"
]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x000000000000000000000000000000000000000000000000000000000000002a","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                                        |
|-----------|--------|----------|----------------------------------------------------|
| `id`      | string | Required | `"1"`                                              |
| `jsonrpc` | string | Required | `"2.0"`                                            |
| `method`  | string | Required | `"eth_call"`                                       |
| `params`  | array  | Requred  | `[ transaction ]` or `[transaction, block_number]` |

