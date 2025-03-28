# trace_replayTransaction RPC Method

Replays a transaction with the exact same state it had when executed originally, returning the trace results.

## Parameters

1. `transaction_hash` - A 32-byte transaction hash, encoded as a hex string prefixed with "0x".
2. `trace_types` - Array of trace types to be returned. Available options include:
   - `"trace"` - Basic transaction execution trace
   - `"vmTrace"` - Full virtual machine execution trace
   - `"stateDiff"` - Information about state changes during execution

## Returns

`Object` - Trace results object containing:
- `output` (string): The return value of the transaction, encoded in hexadecimal
- `trace` (array of objects): Execution traces if requested, containing:
  - `action`: Object describing the action taken in this step
    - `callType`: Type of call (e.g., "call", "delegatecall", "staticcall")
    - `from`: Address of the sender
    - `gas`: Gas provided for the call
    - `input`: Data sent with the call
    - `to`: Address of the receiver
    - `value`: Value transferred
  - `result`:
    - `gasUsed`: Gas used in this step
    - `output`: Return data from the call
  - `subtraces`: Number of child calls
  - `traceAddress`: Path to this call in the call tree
  - `type`: Type of operation
- `vmTrace` (object, optional): Detailed VM execution steps if requested
- `stateDiff` (object, optional): State changes if requested

## Example

### Request

```json
{
  "jsonrpc": "2.0",
  "method": "trace_replayTransaction",
  "params": [
    "0x9c8c7f37fc9c474f3bb5143697d41607b9c882a9f6f8f549d37220abfadf11e4",
    ["trace", "stateDiff"]
  ],
  "id": 1
}
```

### Response

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

## Notes

- This method requires the trace API to be enabled on the node.
- This method replays the transaction exactly as it was executed originally, with the same state and environment.
- Can be particularly useful for debugging transactions that failed or behaved unexpectedly.
- Tracing large or complex transactions may be resource-intensive and could take longer to execute.
