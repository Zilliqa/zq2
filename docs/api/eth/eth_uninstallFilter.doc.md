# Title

eth_uninstallFilter

# Keywords

filter,uninstall,remove

# Description

Uninstalls a filter with given id. Returns `true` if the filter was successfully uninstalled, `false` if the filter was not found.

Filters must be uninstalled when no longer needed. A filter that is not requested with `eth_getFilterChanges` for a period of time will be automatically uninstalled.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "eth_uninstallFilter",
    "params": ["0x16"]
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

| Parameter | Type   | Required | Description                            |
|-----------|--------|----------|----------------------------------------|
| `id`      | string | Required | `"1"`                                  |
| `jsonrpc` | string | Required | `"2.0"`                                |
| `method`  | string | Required | `"eth_uninstallFilter"`                |
| `params`  | array  | Required | `[filter_id]` The hex string filter ID |
