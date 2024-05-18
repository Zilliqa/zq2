# Title

GetBlockchainInfo

# Keywords

blockchain,info,get

# Description

Returns the current network statistics for the specified network. See [https://chainlist.org/?search=zilliqa&testnets=true](https://chainlist.org/?search=zilliqa&testnets=true) for details of deployed chains.

!!! note

    `CHAIN_ID` from `2` to `9` are reserved for Zilliqa Core use.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetBlockchainInfo",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

=== "node.js"

```js
const blockChainInfo = await zilliqa.blockchain.getBlockChainInfo();
console.log(blockChainInfo.result);
```

=== "java"

```java
public class App {
   public static void main(String[] args) throws IOException {
       HttpProvider client = new HttpProvider("{{ _api_url }}");
       Rep<BlockchainInfo> blockchainInfo = client.getBlockchainInfo();
       System.out.println(new Gson().toJson(blockchainInfo));
    }
}
```

=== "python"

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetBlockchainInfo())
```

=== "go"

```go
func GetBlockchainInfo() {
  provider := NewProvider("{{_api_url}}")
  response := provider.GetBlockchainInfo()
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
    "CurrentDSEpoch": "5898",
    "CurrentMiniEpoch": "589778",
    "DSBlockRate": 0.00014142137245459714,
    "NumDSBlocks": "5899",
    "NumPeers": 2400,
    "NumTransactions": "4350627",
    "NumTxBlocks": "589778",
    "NumTxnsDSEpoch": "748",
    "NumTxnsTxEpoch": "4",
    "ShardingStructure": {
      "NumPeers": [600, 600, 600]
    },
    "TransactionRate": 0.09401852277720939,
    "TxBlockRate": 0.014137955733170903
  }
}
```

# Arguments

| Parameter | Type   | Required | Description           |
| --------- | ------ | -------- | --------------------- |
| `id`      | string | Required | `"1"`                 |
| `jsonrpc` | string | Required | `"2.0"`               |
| `method`  | string | Required | `"GetBlockchainInfo"` |
| `params`  | string | Required | Empty string `""`     |


