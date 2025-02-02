# Title

debug_traceBlockByNumber

# Keywords

block,trace

# Description

Accepts a block number and tracer type and will replay the block that is already present in the database

# Curl

```shell
    curl -d '{
        "id": "1",
        "jsonrpc": "2.0",
        "method": "debug_traceBlockByNumber",
        "params": [ 200, {"tracer": "callTracer"} ]
    }' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "type": "CALL",
    "from": "0x0000000000000000000000000000000000000000",
    "to": "0xd46e8dd67c5d32be8058bb8eb970870f07244567",
    "value": "0x0",
    "gas": "0x7fffffffffffadf7",
    "gasUsed": "0x0",
    "input": "0x",
    "output": "0x"
  }
}
```


# Arguments

| Parameter | Type   | Required | Description                     |
|-----------|--------|----------|---------------------------------|
| `id`      | string | Required | `"1"`                           |
| `jsonrpc` | string | Required | `"2.0"`                         |
| `method`  | string | Required | `"debug_traceBlockByNumber"`    |
| `params`  | array  | Required | `[block_number, tracerConfig ]` |

For more details on tracerConfig see https://geth.ethereum.org/docs/interacting-with-geth/rpc/ns-debug#traceconfig
Currently supported tracers are: opcode logger (if no tracer is give), calltracer, 4bytetracer, muxtracer, prestatetracer and jstracer.
