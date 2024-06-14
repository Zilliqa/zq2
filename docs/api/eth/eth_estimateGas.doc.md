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

### Transaction

| Parameter   | Type   | Required | Description                                                                        |
|-------------|--------|----------|------------------------------------------------------------------------------------|
| `from`      | string | required | The address of the sender of this message call                                     |
| `to`        | string | optional | The recipient address                                                              |
| `gas`       | string | optional | Gas to give this message call, as a hex number in a string                         |
| `gas_price` | string | optional | Gas price to give this message call as a hex number in a string                    |
| `data`      | string | required | The calldata                                                                       |
| `value`     | string | optional | Value to send with this call, as a hex number in a string. Assumed 0 if not given. |

### Block number

The block number can be:

 * A hex number in a string: eg. `"0x800"`
 * A block hash as a string eg. `"0xf77e76c25038b0be1fbd12a4f3e404173802bf0c9a9e62deef7949201d59ebfb`
 * `"earliest"` for the earliest block
 * `"latest"` for the latest block
 * `"safe"` for the last block known to be safe.
 * `"finalized"` for the latest finalized block - in Zilliqa 2 this is the same as the `safe` block.
 * `"pending"` is a synonym for `latest`.

If the block number is not given, `latest` is assumed.

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
