# Title

GetDSBlock

# Keywords

DS,block,get

# Description

Returns the details of a specified Directory Service block.
Deprecated in ZQ2; now returns a constant placeholder value.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetDsBlock",
    "params": ["9000"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const dsBlock = await zilliqa.blockchain.getDSBlock("1");
console.log(dsBlock.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<DsBlock> dsBlock = client.getDsBlock("9000
        System.out.println(new Gson().toJson(dsBlock));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetDsBlock("9000"))
```

# Go

```go
func GetDsBlock() {
 provider := NewProvider("{{ _api_url }}")
 response := provider.GetDsBlock("9000
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
      "BlockNum": "9000",
      "Difficulty": 95,
      "DifficultyDS": 156,
      "GasPrice": "2000000000",
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
      "PrevHash": "585373fb2c607b324afbe8f592e43b40d0091bbcef56c158e0879ced69648c8e",
      "Timestamp": "1606443830834512"
    },
    "signature": "7EE023C56602A17F2C8ABA2BEF290386D7C2CE1ABD8E3621573802FA67B243DE60B3EBEE5C4CCFDB697C80127B99CB384DAFEB44F70CD7569F2816DB950877BB"
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                          |
| --------- | ------ | -------- | ---------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                |
| `jsonrpc` | string | Required | `"2.0"`                                              |
| `method`  | string | Required | `"GetDsBlock"`                                       |
| `params`  | string | Required | Specified DS block number to return. Example: `"40"` |
