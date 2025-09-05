# Title

admin_missedViews

# Keywords

admin,jailing,penalty,leader,validators,consensus,view

# Description

Returns information about the missed views that determine the leader of the specified view. The response maps validator public keys to missed view numbers in which the respective validators were the leader. The response also contains the `min_view` that defines the start of the missed view history. If the missed view history is incomplete the methods returns the `Missed view history not available` error message.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "admin_missedViews",
    "params": ["3250"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "min_view": 3124,
    "node_missed_views": {
      "ab035d6cd3321c3b57d14ea09a4f3860899542d2187b5ec87649b1f40980418a096717a671cf62b73880afac252fc5dc": [
        3126,
        3127,
        3129,
        3131,
        3133,
        3141,
        3143,
        3149,
        3156,
        3157,
        3158
      ],
      "b37fd66aef29ca78a82d519a284789d59c2bb3880698b461c6c732d094534707d50e345128db372a1e0a4c5d5c42f49c": [
        3128,
        3130,
        3142
      ],
      "985e3a4d367cbfc966d48710806612cc00f6bfd06aa759340cfe13c3990d26a7ddde63f64468cdba5b2ff132a4639a7f": [
        3132
      ]
    }
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                    |
|-----------|--------|----------|------------------------------------------------|
| `id`      | string | Required | `"1"`                                          |
| `jsonrpc` | string | Required | `"2.0"`                                        |
| `method`  | string | Required | `"admin_missedViews"`                          |
| `params`  | array  | Required | `[view]` The view the leader of which is determined by the missed views|
