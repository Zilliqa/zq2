# Title

eth_estimateGas

# Keywords

eth,gas,get,estimate

# Description

Generate and return an amount of gas that, if supplied at the queried block, would allow a transaction to avoid an out of gas error.

Note that:

 * This is likely to be an overestimate (perhaps a large one).
 * The transaction may run out of gas in any event - because the block at which it will be executed cannot be known when `eth_estimateGas()` is called.
 * The transaction may not succeed in any case - all we guarantee is that it won't run out of gas. It might revert or halt (due to eg. an invalid opcode).

## Parameters

{{ macro_transaction }}

{{ macro_blocknumber_optional }}

# Curl

```sh
curl -d '{
 "id": "1",
 "jsonrpc": "2.0",
 "method": "eth_estimateGas",
 "params": [ {
     "from": "0xcb57ec3f064a16cadb36c7c712f4c9fa62b77415",
     "to": "0x55c3E57617B87c0e24d66b3eB4860a87bFeeF25A",
     "gas": "0x100000",
     "gas_price": "0x1",
     "value": "0x0",
     "data": "0x85bb7d69" },  "latest"
]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x543d","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                                                |
| --------- | ------ | -------- | ---------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                      |
| `jsonrpc` | string | Required | `"2.0"`                                                    |
| `method`  | string | Required | `"DSBlockListing"`                                         |
| `params`  | array  | Requred  | `[ transaction ]` or `[tranasction, block_number]`         |
