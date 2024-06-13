# Title

eth_call

# Keywords

eth,call,contract,call

# Description

Given a transaction and a block number, executes a new message call immediately, without creating a transaction. The result is the result of the contract call.

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

If the block number is not provided, `latest` is assumed.

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
