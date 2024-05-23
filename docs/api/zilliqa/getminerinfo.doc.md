# Title

GetMinerInfo

# Keywords

miner,info,get

# Status

NotYetDocumented

# Description

Returns the mining nodes (i.e., the members of the DS committee and shards) at
the specified DS block.

**Notes:**

1. Nodes owned by Zilliqa Research are omitted.
1. `dscommittee` has no `size` field since the DS committee size is fixed for a
   given chain.
1. For the Zilliqa mainnet, this API is only available from DS block 5500
   onwards.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetMinerInfo",
    "params": ["5500"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "dscommittee": [
      "0x03F25E4B68050496086758C33D16C47792F18D1102BB5DFC0CE5E3A57927008A0B",
      "0x03CF937B2EBE194C72350A6A7E6612C2D8636A33753929F1553E6273442B2F8E5B",
      "0x0372E43C4E7960F02E10F5AFE800E903579E2BE853B160681CBDF7C048FFB78A0F",
      ..."0x0397FD33ED459AD72939CA531385271311DA74094D89109F3876E81BEE84B4E414"
    ],
    "shards": [
      {
        "nodes": [
          "0x0245C0DDAA493700F86A3943260EB04D05DEBD62897E3EC51AE65A704E5C65C0A6",
          "0x0250CF4B40C0C984F2BB005599D2A7503F9C68F701A24CBC10B1EB2533575ADBA7",
          "0x023F2F657F170563E9B28BF837AB295FD13A7E2A4117DB44B2ADFE536F28D28102",
          ..."0x02358F60B4BD90805E6940A901E3C3A5867FFF5BDBD5AD9BFD66FE47C9FA6F1035"
        ],
        "size": 535
      },
      {
        "nodes": [
          "0x02646640964F472CBE1E9BAF2DC5F1A0915AE529DDFF08F28DDE3E460C755DC8C4",
          "0x025EC6741880EC217F921A8FFB4AACDB95FF6477E1BB66CB39950FB2723D3740C8",
          "0x03DE42F6719E8A0147A93604C5F6A4304D14AD5F6A70C011EE37DBFC65D1E7F842",
          ..."0x02B1DB735BF54FC5765D89248DA1C07934282182F3C65CD9152D8F48C539BB5C53"
        ],
        "size": 535
      },
      {
        "nodes": [
          "0x0218C2BA9876BCF3EE9EFF220C9F4CF433F5BE09D9D592F3C657AE7353CFFC3245",
          "0x02BCD61D2F47165E0CD6B3CF9429140C3F017C440DA63E9F44A84503A7D1E41590",
          "0x03E7699C19CFF554D265DC9C797713A7403D99A607EA7C8794259150436EB9FFBB",
          ..."0x031169CB469B6083954F578C19FC7833A90D835AA75942820119272FC6EE4361A5"
        ],
        "size": 534
      }
    ]
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                        |
| --------- | ------ | -------- | ---------------------------------- |
| `id`      | string | Required | `"1"`                              |
| `jsonrpc` | string | Required | `"2.0"`                            |
| `method`  | string | Required | `"GetMinerInfo"`                   |
| `params`  | string | Required | DS block number. Example: `"5500"` |
