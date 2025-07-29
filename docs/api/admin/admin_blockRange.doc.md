# Title

admin_blockRange

# Keywords

admin,block,range,available

# Description

Returns the range of blocks that are available in the local database, indicating the earliest and latest blocks stored on this node.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "admin_blockRange",
    "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": "1..=4096"
}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"admin_blockRange"`        |
| `params`  | array  | Required | Empty array `[]`            |
