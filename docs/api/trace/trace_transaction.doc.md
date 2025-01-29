# Title

trace_transaction

# Keywords

transaction,trace,parity

# Description

Returns all traces of given transaction. The traces are returned in transaction index order and each trace object has the following format.

# Curl

```shell
curl -d '{
"id": "1",
"jsonrpc": "2.0",
"method": "trace_transaction",
"params": ["0x17104ac9d3312d8c136b7f44d4b8b47852618065ebfa534bd2d3b5ef218ca1f3"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "output": "0x",
    "stateDiff": {
      "0x00...01": {
        "balance": {
          "*": {
            "from": "0x100",
            "to": "0x110"
          }
        },
        "code": "=",
        "nonce": "=",
        "storage": {}
      }
    },
    "trace": {
      "action": {
        "from": "0x627306090abab3a6e1400e9345bc60c78a8bef57",
        "gas": "0x1dcd12a0",
        "value": "0x0",
        "callType": "call",
        "input": "0x",
        "to": "0xf12b5dd4ead5f743c6baa640b0216200e89b60da"
      },
      "result": {
        "gasUsed": "0x0",
        "output": "0x"
      },
      "subtraces": 0,
      "traceAddress": [],
      "type": "call"
    }
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                            |
|-----------|--------|----------|----------------------------------------|
| `id`      | string | Required | `"1"`                                  |
| `jsonrpc` | string | Required | `"2.0"`                               |
| `method`  | string | Required | `"trace_transaction"`                  |
| `params`  | array  | Required | `[transactionHash]` Transaction hash   |
