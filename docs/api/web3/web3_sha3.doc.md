# Title

web3_sha3

# Keywords

web3, sha3, hash, cryptographic

# Description

Returns the sha3 hash of the given data.

The input data must be a hex string prefixed with "0x". The output is returned as a hex string prefixed with "0x".

## Parameters

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `data`    | string | Required | Hex string to hash, prefixed with "0x" |

# Curl

```shell
curl -d '{
  "id": "1",
  "jsonrpc": "2.0",
  "method": "web3_sha3",
  "params": ["0x68656c6c6f20776f726c64"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"web3_sha3"`               |
| `params`  | array  | Required | `[ hex_string ]`            |