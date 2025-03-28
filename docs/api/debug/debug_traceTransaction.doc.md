# Title

debug_traceTransaction

# Keywords

transaction,trace,debug

# Description

Returns a detailed trace of all operations performed during the execution of a transaction.

# Curl

```shell
curl -d '{
  "id": "1",
  "jsonrpc": "2.0",
  "method": "debug_traceTransaction",
  "params": [
    "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060",
    {
      "tracer": "callTracer",
      "tracerConfig": {
        "onlyTopCall": false
      }
    }
  ]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "type": "CALL",
    "from": "0x8a0a35f0ea7af034cbedf56bbdcc4b69e45303c9",
    "to": "0xd046c85cb45468e43591f8595e099ae71fb97991",
    "value": "0x0",
    "gas": "0x15f90",
    "gasUsed": "0x54f8",
    "input": "0xa9059cbb0000000000000000000000002eca95dbd37cb526f35ded31c518192c18a8a92e0000000000000000000000000000000000000000000000000000000000989680",
    "output": "0x0000000000000000000000000000000000000000000000000000000000000001",
    "calls": [
      {
        "type": "STATICCALL",
        "from": "0xd046c85cb45468e43591f8595e099ae71fb97991",
        "to": "0xd046c85cb45468e43591f8595e099ae71fb97991",
        "gas": "0xb730",
        "gasUsed": "0x1b3",
        "input": "0x70a08231000000000000000000000000e36ea790bc9d7ab70c55260c66d52b1eca985f84",
        "output": "0x0000000000000000000000000000000000000000000000003635c9adc5dea00000"
      }
    ]
  }
}
```

# Arguments

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | Required | `"1"` |
| `jsonrpc` | string | Required | `"2.0"` |
| `method` | string | Required | `"debug_traceTransaction"` |
| `params` | array | Required | `[transactionHash, traceOptions]` |

The `traceOptions` parameter is an object with the following fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `tracer` | string | `undefined` | Type of tracer to use. Available options: `callTracer`, `prestateTracer`, `4byteTracer`, `noopTracer` |
| `tracerConfig` | object | `{}` | Configuration options for the tracer. Options depend on the tracer used |
| `timeout` | string | `"5s"` | A string specifying the timeout for the tracing |

## Tracer options

### callTracer
Generates a report of all internal calls made during the transaction.

Configuration options:
- `onlyTopCall` (boolean): When true, only traces the main call, not subcalls
- `withLog` (boolean): When true, includes logs in the trace

### prestateTracer
Shows the state of the accounts touched by the transaction before the execution.

Configuration options:
- `diffMode` (boolean): When true, returns the difference between pre and post state

### 4byteTracer
Traces function calls and collects statistics on method calls.

### noopTracer
Performs no tracing but can be used to check if a transaction can be executed successfully.
