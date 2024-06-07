# Title

eth_getBalance

# Keywords

eth,balance,get

# Description

Returns the balance, in `Wei`, of a given account.

Balances are maintained in `Wei` in Zilliqa 2. Because 1 wei = 10^6 ZIL, this value will be 1_000_000 times larger than that given by `GetBalance`.

## Parameters

The block number can be:

 * A hex number in a string: eg. `"0x800"`
 * A block hash as a string eg. `"0xf77e76c25038b0be1fbd12a4f3e404173802bf0c9a9e62deef7949201d59ebfb`
 * `"earliest"` for the earliest block
 * `"latest"` for the latest block
 * `"safe"` for the last block known to be safe.
 * `"finalized"` for the latest finalized block - in Zilliqa 2 this is the same as the `safe` block.
 * `"pending"` is a synonym for `latest`.

# Curl

```shell
curl -d '{
  "id": "1",
  "jsonrpc": "2.0",
  "method": "eth_getBalance",
  "params": [
  "0xcb57ec3f064a16cadb36c7c712f4c9fa62b77415", "latest"
]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x10f0cf064dd59200000","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"DSBlockListing"`          |
| `params`  | array  | Requred  | `[ address, block_number ]` |
