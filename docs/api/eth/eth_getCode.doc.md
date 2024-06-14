# Title

eth_getCode

# Keywords

eth,code,fetch

# Description

If there is EVM code at the given address, return it.

# Curl

```sh
curl -d '{
 "id": "1",
 "jsonrpc": "2.0",
 "method": "eth_estimateGas",
 "params": [ "0xcb57ec3f064a16cadb36c7c712f4c9fa62b77415", "latest" 
 ]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

