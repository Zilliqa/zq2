# Title

GetLatestDSBlock

# Keywords

DS,block,get,latest

# Status

NotYetDocumented

# Description

Returns the details of the most recent Directory Service block.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetLatestDsBlock",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const dsBlock = await zilliqa.blockchain.getLatestDSBlock();
console.log(dsBlock.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<DsBlock> dsBlock = client.getLatestDsBlock();
        System.out.println(new Gson().toJson(dsBlock));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetLatestDsBlock())
```

# Go

```go
func GetLatestDsBlock() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetLatestDsBlock()
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
    "header": {
      "BlockNum": "5898",
      "Difficulty": 91,
      "DifficultyDS": 149,
      "GasPrice": "1000000000",
      "LeaderPubKey": "0x026964CBF00EE542F5CBE80395FFEA747227BC3EFCC21D04956380180A9BE21546",
      "PoWWinners": [
        "0x0219DB403A630022EE014AFD97D02E2DBC6BCEED2506A9E57B5EE5D9EA4F154929",
        "0x02D9C8FC6C87891968ECCEE5EF1CD8A9F8FC32C6463F2FE4E846DFD5C5F45A625E",
        "0x02E07F03C71D26433E7F290416FA43374DA72704F8AA973D4771AA763ACD7C509C",
        "0x02E0FB6CDAEA57738959B493652A74E86339AF2CFE998FB7424BBD7A813450743F",
        "0x0315E9B13D5A5D29902F1EECE0933E96A0AF9939853D5F82B438AAED9F7560B3FC",
        "0x034D9B1B0DC80A0103AE7826886B415C29BF3E814FF6720F6C9C47B57589EFEAAA",
        "0x0394EA64F2F833B88C56464E12B37780BDB9684875F55BC569B397ABE0FCCD8E0E",
        "0x03C53B6C3D901ED46E786DA383BE61A46A442461D2A83379A11A42D7403FB7102E",
        "0x03F6427EE15A5EC409FE7F8CDCC8E7C7704CC07AD2BF8CADFD2A19BB98E80836AF"
      ],
      "PrevHash": "968e2e7820a3795de8c8a7a2e94379cc10f50ada5ea6f90c03c4e61e22ee83b5",
      "Timestamp": "1590641169078644"
    },
    "signature": "803D64288A6F827DAFA529235C7A78E7BC2D1C882C5DA643E03CB0B2A786C7A5508CCD5F409CDAA325709E4E9A98F1D67596E61CB8CF958AD98B7DB842F87A44"
  }
}
```

# Arguments

| Parameter | Type   | Required | Description          |
| --------- | ------ | -------- | -------------------- |
| `id`      | string | Required | `"1"`                |
| `jsonrpc` | string | Required | `"2.0"`              |
| `method`  | string | Required | `"GetLatestDsBlock"` |
| `params`  | string | Required | Empty string `""`    |
