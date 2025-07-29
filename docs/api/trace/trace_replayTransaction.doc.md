# Title

trace_replayTransaction

# Keywords

transaction,trace,replay,parity

# Description

Replays a transaction with the exact same state it had when executed originally, returning the trace results.
This method requires the trace API to be enabled on the node and replays the transaction exactly as it was executed originally, with the same state and environment.
Can be particularly useful for debugging transactions that failed or behaved unexpectedly.
Tracing large or complex transactions may be resource-intensive and could take longer to execute.

# Curl

```shell
curl -d '{
  "id": "1",
  "jsonrpc": "2.0",
  "method": "trace_replayTransaction",
  "params": [
    "0x9c8c7f37fc9c474f3bb5143697d41607b9c882a9f6f8f549d37220abfadf11e4",
    ["trace", "stateDiff"]
  ]
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
      "0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c": {
        "balance": {
          "*": {
            "from": "0x43ec6d330810b27f",
            "to": "0x43ec6d330bb8dbf"
          }
        },
        "code": "=",
        "nonce": {
          "*": {
            "from": "0x1c2",
            "to": "0x1c3"
          }
        },
        "storage": {}
      }
    },
    "trace": [
      {
        "action": {
          "callType": "call",
          "from": "0x5a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c",
          "gas": "0x9c40",
          "input": "0x",
          "to": "0xc083e9947cf02b8ffc7d3090ae9aea72df98fd47",
          "value": "0x340aad21b3b700000"
        },
        "result": {
          "gasUsed": "0x51f4",
          "output": "0x"
        },
        "subtraces": 0,
        "traceAddress": [],
        "type": "call"
      }
    ],
    "vmTrace": null
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                                                           |
|-----------|--------|----------|---------------------------------------------------------------------------------------|
| `id`      | string | Required | `"1"`                                                                                |
| `jsonrpc` | string | Required | `"2.0"`                                                                              |
| `method`  | string | Required | `"trace_replayTransaction"`                                                          |
| `params`  | array  | Required | `[transaction_hash, trace_types]` Transaction hash (32-byte hex string) and array of trace types to return |

The `transaction_hash` parameter is a 32-byte transaction hash, encoded as a hex string prefixed with "0x".

The `trace_types` parameter is an array of trace types to be returned. Available options include:
- `"trace"` - Basic transaction execution trace
- `"vmTrace"` - Full virtual machine execution trace
- `"stateDiff"` - Information about state changes during execution

The response object contains:
- `output` (string): The return value of the transaction, encoded in hexadecimal
- `trace` (array): Execution traces if requested, containing action details, results, subtraces count, trace address path, and operation type
- `vmTrace` (object, optional): Detailed VM execution steps if requested
- `stateDiff` (object, optional): State changes if requested
