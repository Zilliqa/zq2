# Title

GetTxBlockVerbose

# Keywords

tx,block,get,verbose,number

# Description

`GetTxBlockVerbose` returns the verbose details of a specified transaction block

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetTxBlockVerbose",
    "params": ["1002353"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "B1": [
      false,
      false,
      false
      // Output truncated
    ],
    "B2": [
      false,
      false
      // Output truncated
    ],
    "CS1": "FBA696961142862169D03EED67DD302EAB91333CBC4EEFE7EDB230515DA31DC1B9746EEEE5E7C105685E22C483B1021867B3775D30215CA66D5D81543E9FE8B5",
    "PrevDSHash": "585373fb2c607b324afbe8f592e43b40d0091bbcef56c158e0879ced69648c8e",
    "header": {
      "BlockNum": "9000",
      "CommitteeHash": "da38b3b21b26b71835bb1545246a0a248f97003de302ae20d70aeaf854403029",
      "Difficulty": 95,
      "DifficultyDS": 156,
      "EpochNum": "899900",
      "GasPrice": "2000000000",
      "MembersEjected": [
        "0x02572A2FCD59F8115297B399F76D7ACCFDA7E82AC53702063C3A61FB4D85E0D0C1",
        "0x029933F07FF634654C2ECB17A90EAD00CF9EE9F75395E206660CCEFB21874ECEA1",
        "0x02AAD92E5A3C9D8ECB364225719478B51026DD5C786BF7312C5C9765353BC4C98B"
      ],
      "PoWWinners": [
        "0x0207184EB580333132787B360CA6D93290000C9F71E0B6A02C4412E7148FB1AF81",
        "0x0285B572471A9D3BA729719ED2EEE86395D3B8F243572E9099A5E8B750F46092A7",
        "0x02C1D8C0C7884E65A22FFD76DF9ACC2EA3551133E4ADD59C2DF74F327E09F709FF",
        "0x02D728E77C8DA14E900BA8A2014A0D4B5512C6BABCCB77B83F21381437E0038F44",
        "0x0321B0E1A20F02C99394DD24B34AB4E79AE6CBF0C689C222F246431A764D6B59DB",
        "0x038A724504899CCCA068BD165AE15CE2947667225C72912039CEE4EF3992334843",
        "0x03AB477A7A895DD4E84F240A2F1FCF5F86B1A3D59B6AD3065C18CD69729D089959",
        "0x03B29C7F3F85329B0621914AB0367BA78135889FB8E4F937DDB7DAA8123AD4DF3C",
        "0x03E82B00B53ECC10073404E844841C519152E500A655EEF1D8EAD6612ABDF5B552"
      ],
      "PoWWinnersIP": [
        {
          "IP": "34.212.122.139",
          "port": 33133
        },
        {
          "IP": "34.214.85.15",
          "port": 33133
        },
        {
          "IP": "54.148.246.51",
          "port": 33133
        },
        {
          "IP": "54.218.112.25",
          "port": 33133
        },
        {
          "IP": "54.184.108.224",
          "port": 33133
        },
        {
          "IP": "34.211.53.138",
          "port": 33133
        },
        {
          "IP": "44.234.38.187",
          "port": 33133
        },
        {
          "IP": "44.234.126.143",
          "port": 33133
        },
        {
          "IP": "34.223.254.106",
          "port": 33133
        }
      ],
      "PrevHash": "585373fb2c607b324afbe8f592e43b40d0091bbcef56c158e0879ced69648c8e",
      "ReservedField": "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "SWInfo": {
        "Scilla": [0, 0, 0, "0", 0],
        "Zilliqa": [0, 0, 0, "0", 0]
      },
      "ShardingHash": "3216a33bfd4801e1907e72c7d529cef99c38d57cd281d0e9d726639fd9882d25",
      "Timestamp": "1606443830834512",
      "Version": 2
    },
    "signature": "7EE023C56602A17F2C8ABA2BEF290386D7C2CE1ABD8E3621573802FA67B243DE60B3EBEE5C4CCFDB697C80127B99CB384DAFEB44F70CD7569F2816DB950877BB"
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                               |
| --------- | ------ | -------- | --------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                     |
| `jsonrpc` | string | Required | `"2.0"`                                                   |
| `method`  | string | Required | `"GetTxBlockVerbose"`                                     |
| `params`  | string | Required | Specified TX block number to return. Example: `"1002353"` |


