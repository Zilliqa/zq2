# Title

GetLatestTxBlock

# Keywords

Tx,block,get,latest

# Description

Returns the details of the most recent Transaction block.
Deprecated in ZQ2; now returns a constant placeholder value.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetLatestTxBlock",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const txBlock = await zilliqa.blockchain.getLatestTxBlock();
console.log(txBlock.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<TxBlock> txBlock = client.getLatestTxBlock();
        System.out.println(new Gson().toJson(txBlock));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetLatestTxBlock())
```

# Go

```go
func GetLatestTxBlock() {
   provider := NewProvider("{{ _api_url }}")
   response := provider.GetLatestTxBlock()
   result, _ := json.Marshal(response)
   fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": {
    "body": {
      "BlockHash": "53a24881823dd5f2a3dfda5902d1b79710e2bec5477ed3aa7325d74e30436b58",
      "HeaderSign": "8E0C73945CC2282173CF8CF44D7EB55E5DAD9B2D6D3437C6AC09DE8CF0D6B698575E535168AA898B6B3A3107603BDFC4BC671A4621E77C9004369FC3513F53A0",
      "MicroBlockInfos": [
        {
          "MicroBlockHash": "ebadc2d6e80b749e6e322ae54467d516618ea79d1ae495f26f3592c70b4de71a",
          "MicroBlockShardId": 0,
          "MicroBlockTxnRootHash": "165049b84c5f4499ce781aab63cba06aa31ed4e1b556f0aac643f01eb5814da4"
        },
        {
          "MicroBlockHash": "7111f32a526a381ecb3492e21a382f2dc5ad10c346340aaae3addd1a349cc559",
          "MicroBlockShardId": 1,
          "MicroBlockTxnRootHash": "640a7019993fcdaec2bfd10b50f5f9faea92920a1a4c0cb931ae56e061f983d9"
        },
        {
          "MicroBlockHash": "1a914f52aaef51fa3d585c666e56ae55c2dc5e3b8c759c66d1b79b211b783d0e",
          "MicroBlockShardId": 2,
          "MicroBlockTxnRootHash": "aea9eafc983f75947ef63d0aedd14c0c138025cbbaa5934f3ef327b2116bfd68"
        },
        {
          "MicroBlockHash": "cf095207f2f3cece2bc21f172022e2e3473c8a9279ba67a4d9bd1e352890f496",
          "MicroBlockShardId": 3,
          "MicroBlockTxnRootHash": "d97261b9c32ca9d1cfc8431a64523c9e3d26beff7e5265c5d431d5a41b416e49"
        }
      ]
    },
    "header": {
      "BlockNum": "1002353",
      "DSBlockNum": "10024",
      "GasLimit": "650000",
      "GasUsed": "25517",
      "MbInfoHash": "b2a862649507a9d86b21246b1538aa237c75f65cf7ef9a512e03ba39d0e62933",
      "MinerPubKey": "0x02134CC19B594B1571916AABBA4475026D1B2021C19045CB2065E0D3B12706768E",
      "NumMicroBlocks": 4,
      "NumPages": 5,
      "NumTxns": 10022,
      "PrevBlockHash": "18426f28438c500dd8b424f7923844290f4f082d43e84262ce629eebce68b82c",
      "Rewards": "0",
      "StateDeltaHash": "9e2c6b2b542219e421792892e8d42923f30fd3e4d4c55369feb89e3979b5a3a7",
      "StateRootHash": "57710511d91f7ec765c264babd53d6b607b320167029cc88c477fafd78c14632",
      "Timestamp": "1612477810820092",
      "TxnFees": "51138500000000",
      "Version": 1
    }
  }
}
```

# Arguments

| Parameter | Type   | Required | Description          |
| --------- | ------ | -------- | -------------------- |
| `id`      | string | Required | `"1"`                |
| `jsonrpc` | string | Required | `"2.0"`              |
| `method`  | string | Required | `"GetLatestTxBlock"` |
| `params`  | string | Required | Empty string `""`    |
