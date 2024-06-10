# Title

eth_getCode

# Keywords

eth,code,fetch

# Description

If there is code at the given address, return it.

Following the Zilliqa 1 behaviour, if you call `eth_getCode()` on a Scilla contract, the Scilla source code will be returned.

## Parameters

{{ macro_address }}

{{ macro_blocknumber }}

# Curl

```sh
curl -d '{
 "id": "1",
 "jsonrpc": "2.0",
 "method": "eth_estimateGas",
 "params": [ "0xcb57ec3f064a16cadb36c7c712f4c9fa62b77415", "latest" 
 ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```sh
{"jsonrpc":"2.0","result":"0x7363696c6c615f76657273696f6e20300a0a636f6e74726163742048656c6c6f4576656e747328290a0a7472616e736974696f6e2053656e644576656e7428290a202065203d207b205f6576656e746e616d653a202248656c6c6f223b20206d6573736167653a2022576f726c6422207d3b0a20206576656e7420650a656e640a0a","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description               |
|-----------|--------|----------|---------------------------|
| `id`      | string | Required | `"1"`                     |
| `jsonrpc` | string | Required | `"2.0"`                   |
| `method`  | string | Required | `"eth_call"`              |
| `params`  | array  | Required | `[address, block_number]` |
