# Title

eth_getUncleByBlockHashAndIndex

# Keywords

eth,uncle,hash,get,index

# Description

Retrieves an uncle by block hash and index into the uncles list for that block. In ZQ2, always returns `null`, regardless of arguments.

# Curl

```sh
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getUncleByBlockHashAndIndex",
    "params": [ "0x6ec76875872a1063ba4e4bedcfd0e8d9e127b2d11f8be38e1a91fdd103860df4", "0x0"
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
| `method`  | string | Required | `"eth_getUncleByBlockHashAndIndex"` |
| `params`  | array  | Requred  | can be anything                       |
