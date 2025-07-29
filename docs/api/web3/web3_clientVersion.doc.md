# Title

web3_ClientVersion

# Keywords

web3,client,version,get

# Description

Returns the current version string of the running Zilliqa node in `<name>/<version>` format.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "web3_clientVersion",
    "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
    "id": "1",
    "jsonrpc": "2.0",
    "result": "zilliqa2/v2.0.0"
}
```

# Arguments

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `id` | string | Required | `"1"` |
| `jsonrpc` | string | Required | `"2.0"` |
| `method` | string | Required | `"web3_clientVersion"` |
| `params` | array | Required | Empty array `[]` |
