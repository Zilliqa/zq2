# Title

admin_getLeaders

# Keywords

admin,leaders,validators,consensus,view

# Description

Returns information about the consensus leaders for a range of views starting from a specified view. The response includes view numbers and corresponding validator information.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "admin_getLeaders",
    "params": ["0x1000", "0x5"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": [
    [
      4096,
      {
        "public_key": "0x026964CBF00EE542F5CBE80395FFEA747227BC3EFCC21D04956380180A9BE21546",
        "peer_id": "12D3KooWBmwkafWE9JFWqFBe7tBXm1Q4t6R2nV4p8J3xQ5m7L9kS",
        "stake": "1000000000000000000000"
      }
    ],
    [
      4097,
      {
        "public_key": "0x03C53B6C3D901ED46E786DA383BE61A46A442461D2A83379A11A42D7403FB7102E",
        "peer_id": "12D3KooWCrMTaGRNkpqXeQBrv4RqP8Kd2wNmH5xY7zA9BcEfGhIj",
        "stake": "2000000000000000000000"
      }
    ],
    [
      4098,
      {
        "public_key": "0x034D9B1B0DC80A0103AE7826886B415C29BF3E814FF6720F6C9C47B57589EFEAAA",
        "peer_id": "12D3KooWDxMnP7qR8sKfWe5YnT4vBcDfGhIjK3L9mNpQ2rStUvWx",
        "stake": "1500000000000000000000"
      }
    ],
    [
      4099,
      {
        "public_key": "0x0394EA64F2F833B88C56464E12B37780BDB9684875F55BC569B397ABE0FCCD8E0E",
        "peer_id": "12D3KooWEfGhIjK3L9mNpQ2rStUvWxYzAbCdEfGhIjK3L9mNpQ2r",
        "stake": "3000000000000000000000"
      }
    ],
    [
      4100,
      {
        "public_key": "0x03F6427EE15A5EC409FE7F8CDCC8E7C7704CC07AD2BF8CADFD2A19BB98E80836AF",
        "peer_id": "12D3KooWGhIjK3L9mNpQ2rStUvWxYzAbCdEfGhIjK3L9mNpQ2rSt",
        "stake": "2500000000000000000000"
      }
    ]
  ]
}
```

# Arguments

| Parameter | Type   | Required | Description                                    |
|-----------|--------|----------|------------------------------------------------|
| `id`      | string | Required | `"1"`                                          |
| `jsonrpc` | string | Required | `"2.0"`                                        |
| `method`  | string | Required | `"admin_getLeaders"`                           |
| `params`  | array  | Required | `[start_view, count]` Starting view and number of leaders to return (max 100) |
