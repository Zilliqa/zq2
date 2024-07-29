# Title

eth_getUncleCountByBlockNumber

# Keywords

eth,uncle,number,count

# Description

Retrieves number of uncles by block number. Always returns "`0x0`", regardless of the arguments.

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getUncleCountByBlockNumber",
    "params": [ "0x4"
 ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x0","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                        |
|-----------|--------|----------|------------------------------------|
| `id`      | string | Required | `"1"`                              |
| `jsonrpc` | string | Required | `"2.0"`                            |
| `method`  | string | Required | `"eth_getUncleCountByBlockNumber"` |
| `params`  | array  | Requred  | can be anything                    |

