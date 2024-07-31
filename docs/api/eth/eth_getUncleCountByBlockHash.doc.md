# Title

eth_getUncleCountByBlockHash

# Keywords

eth,uncle,count,hash

# Description

Retrieves number of uncles in a block from a block matching the given block hash. Always returns `"0x0"`, regardless of the arguments.

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getUncleCountByBlockHash",
    "params": [ "0x1d6fea3e5707aa24a7a1ce6f661adab0655c2e2438dddee16dacdf3d6cf14ee4"
 ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x0","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                      |
|-----------|--------|----------|----------------------------------|
| `id`      | string | Required | `"1"`                            |
| `jsonrpc` | string | Required | `"2.0"`                          |
| `method`  | string | Required | `"eth_getUncleCountByBlockHash"` |
| `params`  | array  | Requred  | can be anything                  |
