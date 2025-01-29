# Title

trace_filter

# Keywords

trace,filter,parity

# Description

Returns traces matching given filter. The traces are returned in transaction index order.

# Curl

```shell
curl -d '{
"id": "1",
"jsonrpc": "2.0",
"method": "trace_filter",
"params": [{
  "fromBlock": "0x2ed119",
  "toBlock": "0x2ed119",
  "fromAddress": ["0x1c39ba39e4735cb65978d4db400ddd70a72dc750"],
  "toAddress": ["0x2910543af39aba0cd09dbb2d50200b3e800a63d2"],
  "after": 0,
  "count": 100
}]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": [
    {
      "output": "0x",
      "stateDiff": null,
      "trace": [{
        "action": {
          "from": "0x1c39ba39e4735cb65978d4db400ddd70a72dc750",
          "gas": "0x0",
          "value": "0x1",
          "callType": "call",
          "to": "0x2910543af39aba0cd09dbb2d50200b3e800a63d2"
        },
        "result": {
          "gasUsed": "0x0",
          "output": "0x"
        },
        "subtraces": 0,
        "traceAddress": [],
        "type": "call"
      }],
      "vmTrace": null
    }
  ]
}
```

# Arguments

| Parameter | Type   | Required | Description                                          |
|-----------|--------|----------|------------------------------------------------------|
| `id`      | string | Required | `"1"`                                               |
| `jsonrpc` | string | Required | `"2.0"`                                            |
| `method`  | string | Required | `"trace_filter"`                                   |
| `params`  | array  | Required | `[filterOptions]` Object containing filter options: |

Filter Options:

- `fromBlock`: `BlockNumber` - (optional) From this block
- `toBlock`: `BlockNumber` - (optional) To this block
- `fromAddress`: `[Address]` - (optional) Sent from these addresses
- `toAddress`: `[Address]` - (optional) Sent to these addresses
- `after`: `Integer` - (optional) The offset trace number
- `count`: `Integer` - (optional) Integer number of traces to display in a batch
