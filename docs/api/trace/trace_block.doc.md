# Title

trace_block

# Keywords

block,trace,parity

# Description

Returns traces created at given block. The traces are returned in transaction index order.

# Curl

```shell
curl -d '{
"id": "1",
"jsonrpc": "2.0",
"method": "trace_block",
"params": ["0x2ed119"]
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

| Parameter | Type   | Required | Description                     |
|-----------|--------|----------|---------------------------------|
| `id`      | string | Required | `"1"`                          |
| `jsonrpc` | string | Required | `"2.0"`                        |
| `method`  | string | Required | `"trace_block"`                |
| `params`  | array  | Required | `[blockNumber]` Block number or tag |
