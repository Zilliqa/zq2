# Title

admin_importViewHistory

# Keywords

admin,jailing,penalty,leader,validators,consensus,view

# Description

Imports the missed view history from a checkpoint file specified as input parameter up to the first missed view already present in the node's missed view history. There must not be any gap between the node's current missed view history and the histored imported from the checkpoint. The length of the imported history will be adjusted according to the node's `max_missed_view_age` setting and the `min_view` will also be updated accordingly.

This RPC method is used to avoid the need for re-syncing archive nodes before the jailing hardfork is activated. The only thing the node operator has to do is to import the missed view history reaching back to the genesis / switchover block from a recent checkpoint. Consequently, the `load_checkpoint` settings should be ommitted in the config file.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "admin_importViewHistory",
    "params": ["001641600.ckpt"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": null
}
```

# Arguments

| Parameter | Type   | Required | Description                                    |
|-----------|--------|----------|------------------------------------------------|
| `id`      | string | Required | `"1"`                                          |
| `jsonrpc` | string | Required | `"2.0"`                                        |
| `method`  | string | Required | `"admin_importViewHistory"`                    |
| `params`  | array  | Required | `[path]` The path to the checkpoint file to import the history from|
