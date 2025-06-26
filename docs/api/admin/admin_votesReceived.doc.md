# Title

admin_votesReceived

# Keywords

admin,votes,received,consensus,validators

# Description

Returns detailed information about votes received by the consensus engine, including block votes, new view votes, and buffered votes. Also shows which validators have voted and which have not.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "admin_votesReceived",
    "params": []
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "votes": [
      [
        "0x7d8b4e2f3a1c9e5d8b6f4a2e1c9d7b5a3e8f6c4d2a9b7e5c8f1d4a6b9c2e7f5a",
        {
          "signature": "0xa31bb94ff29d0c1d0d1e5e79cc798051d7721255e49fbdb5dffc50e9a641247d7173c9e3673539593092b1746fa573fe12fb510436086e62f2c7fc1fddf18d18f5e7a3a7168965b67fc2aa70da89ac36cca8b90bdf54861415e9092ea34826f3",
          "cosigned": "[1, 0, 1, 1]",
          "view": "0x4f5f",
          "block_hash": "0xec294892c9d8d325483eb26af35dca5801113d50a4e8ab0f85cfa15a44a7b65e"
        },
        {
          "voted": [
            "0x026964CBF00EE542F5CBE80395FFEA747227BC3EFCC21D04956380180A9BE21546",
            "0x03C53B6C3D901ED46E786DA383BE61A46A442461D2A83379A11A42D7403FB7102E"
          ],
          "not_voted": [
            "0x034D9B1B0DC80A0103AE7826886B415C29BF3E814FF6720F6C9C47B57589EFEAAA"
          ]
        }
      ]
    ],
    "buffered_votes": [
      [
        "0x8e3d2a1f5c7b9e4d6a8f2c5e9b1d7a3f6c8e2a5d9b7f4c1e8a6d3f9b5c2e7a4",
        [
          [
            "12D3KooWBmwkafWE9JFWqFBe7tBXm1Q4t6R2nV4p8J3xQ5m7L9kS",
            {
              "signature": "0xb45c7d8e9f1a2b6c3e7d9f2a5b8c1e4d7f9a2c5e8b1d4f7a9c2e5b8d1f4a7c9",
              "view": "0x4f61",
              "block_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            }
          ]
        ]
      ]
    ],
    "new_views": [
      [
        100,
        {
          "signature": "0xc56d8e9f2a3b7c4e8d1f5a9b2c6e9d2f5a8c1e4d7f9a2c5e8b1d4f7a9c2e5b8",
          "cosigned": "[1, 1, 0, 1]",
          "view": "0x64",
          "high_qc": {
            "signature": "0xd67e9f1a3b8c5e9d2f6a9c3e7d1f5a8b2c6e9d2f5a8c1e4d7f9a2c5e8b1d4f7",
            "cosigned": "[1, 0, 1, 1]",
            "view": "0x63",
            "block_hash": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
          }
        },
        {
          "voted": [
            "0x026964CBF00EE542F5CBE80395FFEA747227BC3EFCC21D04956380180A9BE21546",
            "0x03C53B6C3D901ED46E786DA383BE61A46A442461D2A83379A11A42D7403FB7102E",
            "0x034D9B1B0DC80A0103AE7826886B415C29BF3E814FF6720F6C9C47B57589EFEAAA"
          ],
          "not_voted": [
            "0x0394EA64F2F833B88C56464E12B37780BDB9684875F55BC569B397ABE0FCCD8E0E"
          ]
        }
      ]
    ]
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                 |
|-----------|--------|----------|-----------------------------|
| `id`      | string | Required | `"1"`                       |
| `jsonrpc` | string | Required | `"2.0"`                     |
| `method`  | string | Required | `"admin_votesReceived"`     |
| `params`  | array  | Required | Empty array `[]`            |
