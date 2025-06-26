# Title

admin_generateCheckpoint

# Keywords

admin,checkpoint,generate,snapshot

# Description

Generates a checkpoint (snapshot) of the blockchain state at a specified block. Returns the checkpoint file name, hash, and block number.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "admin_generateCheckpoint",
    "params": ["0x1000"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "file_name": "checkpoint_4096.tar.gz",
    "hash": "0x7d8b4e2f3a1c9e5d8b6f4a2e1c9d7b5a3e8f6c4d2a9b7e5c8f1d4a6b9c2e7f5a",
    "block": "0x1000"
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                           |
|-----------|--------|----------|---------------------------------------|
| `id`      | string | Required | `"1"`                                 |
| `jsonrpc` | string | Required | `"2.0"`                               |
| `method`  | string | Required | `"admin_generateCheckpoint"`          |
| `params`  | array  | Required | `[block_id]` Block ID to checkpoint   |
