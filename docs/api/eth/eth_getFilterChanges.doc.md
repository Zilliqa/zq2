# Title

eth_getFilterChanges

# Keywords

filter,changes,get,polling

# Description

Polling method for a filter, which returns an array of logs, block hashes, or transaction hashes that occurred since the last poll.

The response format depends on the filter type:
- For log filters: Returns an array of logs
- For block filters: Returns an array of block hashes
- For pending transaction filters: Returns an array of transaction hashes

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getFilterChanges",
    "params": ["0x16"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": ["0x78d856462ada..."] // Array of values based on filter type
}
```

# Arguments

| Parameter | Type   | Required | Description                                |
|-----------|--------|----------|--------------------------------------------|
| `id`      | string | Required | `"1"`                                      |
| `jsonrpc` | string | Required | `"2.0"`                                    |
| `method`  | string | Required | `"eth_getFilterChanges"`                   |
| `params`  | array  | Required | `[filter_id]` The hex string filter ID     |
