# Title

GetSmartContractInit

# Keywords

contract,init,get

# Description

Returns the initialization (immutable) parameters of a given smart contract, represented in a JSON format.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetSmartContractInit",
    "params": ["fe001824823b12b58708bf24edd94d8b5e1cfcf7"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const smartContractInit = await zilliqa.blockchain.getSmartContractInit(
  "fe001824823b12b58708bf24edd94d8b5e1cfcf7"
);
console.log(smartContractInit.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<List<Contract.State>> smartContractInit = client.getSmartContractInit("fe001824823b12b58708bf24edd94d8b5e1cfcf7");
        System.out.println(new Gson().toJson(smartContractInit));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetSmartContractInit("fe001824823b12b58708bf24edd94d8b5e1cfcf7"))
```

# Go

```go
func GetSmartContractInit() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetSmartContractInit("fe001824823b12b58708bf24edd94d8b5e1cfcf7")
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": [
    {
      "type": "Uint32",
      "value": "0",
      "vname": "_scilla_version"
    },
    {
      "type": "ByStr20",
      "value": "0x67a08f4aefbe1798970be37dc3d0c7954be349de",
      "vname": "owner"
    },
    {
      "type": "BNum",
      "value": "140",
      "vname": "_creation_block"
    },
    {
      "type": "ByStr20",
      "value": "0x65fc5463805e3d7c753392e8a1e721aebda8d27f",
      "vname": "_this_address"
    }
  ]
}
```

# Arguments

| Parameter | Type   | Required | Description                                                                                                                                                                                             |
| --------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                                                                                                                                                                   |
| `jsonrpc` | string | Required | `"2.0"`                                                                                                                                                                                                 |
| `method`  | string | Required | `"GetSmartContractInit"`                                                                                                                                                                                |
| `params`  | string | Required | A smart contract address of 20 bytes. <br/> Example: `"fe001824823b12b58708bf24edd94d8b5e1cfcf7"` <br/><br/> Also supports Bech32 address <br/> Example: `"zil1lcqpsfyz8vfttpcghujwmk2d3d0pel8h3qptyu"` |


