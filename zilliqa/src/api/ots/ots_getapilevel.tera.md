---
id: api/ots/ots_getApiLevel
title: ots_getApiLevel
---

---
{% api_header %}

{% api_example_request %}

{% api_curl %}

```shell
    curl -d '{
        "id": "1",
        "jsonrpc": "2.0",
        "method": "ots_getApiLevel",
        "params": [ ]
    }' -H "Content-Type: application/json" -X POST "https://api.zq2-devnet.zilliqa.com/"
```

{% api_example_response %}

```json
{
  "jsonrpc": "2.0",
  "result": 8,
  "id": "1"
}
```

{% api_arguments %}

{% api_none %}

---
