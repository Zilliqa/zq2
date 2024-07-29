# Title

eth_protocolVerrsion

# Keywords

eth,version.protocol

# Description

Retrieve the ethereum protocol version number. zq2 nodes always return "0x41".

# Curl

```sh
curl -d '{
   "id": "1",
   "jsonrpc": "2.0",
   "method": "eth_protocolVersion",
   "params": [
]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```


# Response

```
{"jsonrpc":"2.0","result":"0x41","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description     |
|-----------|--------|----------|-----------------|
| `id`      | string | Required | `"1"`           |
| `jsonrpc` | string | Required | `"2.0"`         |
| `method`  | string | Required | `"eth_protocolVersion"`  |
| `params`  | array  | Requred  | can be anything |
