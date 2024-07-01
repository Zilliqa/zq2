# Title

eth_getStorageAt

# Keywords

storage,fetch,get,eth

# Description

Return the value of a storage location at a given address.


!!! note

    The way that storage is encoded is different (and subject to
    change) between Scilla and EVM contracts. Whilst `eth_getStorageAt()`
    may not fail if called on an address containing Scilla code, it will
    not return meaningful results.

## Parameters

{{ macro_address }}

### Storage slot

A hex encoded 256-bit unsigned integer which determines the storage slot to inspect.

{{ macro_blockid }}

# Curl

```sh
curl -d '{
   "id": "1",
   "jsonrpc": "2.0",
   "method": "eth_getStorageAt",
   "params": [ "0xbCa0F6F4CbfE8AC37096B674dE8F96C701C43f7c", "0x0", "latest" 
]}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{"jsonrpc":"2.0","result":"0x000000000000000000000000cb57ec3f064a16cadb36c7c712f4c9fa62b77415","id":"1"}
```

# Arguments

| Parameter | Type   | Required | Description               |
|-----------|--------|----------|---------------------------|
| `id`      | string | Required | `"1"`                     |
| `jsonrpc` | string | Required | `"2.0"`                   |
| `method`  | string | Required | `"eth_getStorageAt"`              |
| `params`  | array  | Required | `[address, storage_slot, block_number]` |
