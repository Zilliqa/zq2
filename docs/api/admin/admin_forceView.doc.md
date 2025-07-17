# Title

admin_forceView

# Keywords

admin,force,view,consensus,timeout

# Description

Forces the consensus engine to move to a specific view with a custom timeout. This is an administrative function that can be used to manually advance consensus when needed.

!!! warning
    This is a powerful administrative function that can affect consensus operation. Use with caution.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "admin_forceView",
    "params": ["0x1000", "30s"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": true
}
```

# Arguments

| Parameter | Type   | Required | Description                           |
|-----------|--------|----------|---------------------------------------|
| `id`      | string | Required | `"1"`                                 |
| `jsonrpc` | string | Required | `"2.0"`                               |
| `method`  | string | Required | `"admin_forceView"`                   |
| `params`  | array  | Required | `[view, timeout_at]` View number and timeout specification |
