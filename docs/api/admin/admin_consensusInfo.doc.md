# Title

admin_consensusInfo

# Keywords

admin,consensus,info,view,qc

# Description

Returns detailed information about the current consensus state of the node, including the current view, high quorum certificate, and timing information about view changes.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "admin_consensusInfo",
    "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "view": "0x4f60",
    "high_qc": {
      "signature": "0xa31bb94ff29d0c1d0d1e5e79cc798051d7721255e49fbdb5dffc50e9a641247d7173c9e3673539593092b1746fa573fe12fb510436086e62f2c7fc1fddf18d18f5e7a3a7168965b67fc2aa70da89ac36cca8b90bdf54861415e9092ea34826f3",
      "cosigned": "[1, 0, 1, 1]",
      "view": "0x4f5f",
      "block_hash": "0xec294892c9d8d325483eb26af35dca5801113d50a4e8ab0f85cfa15a44a7b65e"
    },
    "milliseconds_since_last_view_change": 5000,
    "milliseconds_until_next_view_change": 15000
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"admin_consensusInfo"`     |
| `params`  | array  | Required | Empty array `[]`            |
