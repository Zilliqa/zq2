# Title

eth_getUncleByBlockHashAndIndex

# Keywords

eth,uncle,count,block,index

# Description

Retrieves an uncle by block number and index into the uncles list. Always returns `null`, regardless of arguments.

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getUncleByBlockNumberAndIndex",
    "params": [ "0x204", "0x0"
 ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":null,"id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description                           |
|-----------|--------|----------|---------------------------------------|
| `id`      | string | Required | `"1"`                                 |
| `jsonrpc` | string | Required | `"2.0"`                               |
| `method`  | string | Required | `"eth_getUncleByBlockNumberAndIndex"` |
| `params`  | array  | Requred  | can be anything                       |
