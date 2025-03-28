# Title

eth_getFilterLogs

# Keywords

filter,logs,get

# Description

Returns an array of all logs matching filter with given id.

!!! note
    Can only be used with log filters - will return an error if used with block or pending transaction filters.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_getFilterLogs",
    "params": ["0x16"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": [
    {
      "removed": false,
      "logIndex": "0x0",
      "transactionIndex": "0x0",
      "transactionHash": "0x78d856462ada...",
      "blockHash": "0x1234...",
      "blockNumber": "0x1b4",
      "address": "0xd5a37dc5c9a396a03dd152c39319f4443f79c6da",
      "data": "0x0000000000000000000000000000000000000000000000000000000000000001",
      "topics": ["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]
    }
  ]
}
```

# Arguments

| Parameter | Type   | Required | Description                            |
|-----------|--------|----------|----------------------------------------|
| `id`      | string | Required | `"1"`                                  |
| `jsonrpc` | string | Required | `"2.0"`                                |
| `method`  | string | Required | `"eth_getFilterLogs"`                  |
| `params`  | array  | Required | `[filter_id]` The hex string filter ID |
