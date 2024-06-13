# Title

GetSmartContractState

# Keywords

get,contract,state

# Description

Returns the state (mutable) variables of a smart contract address in JSON format.

!!! note

    The way that storage is encoded is different (and subject to
    change) between Scilla and EVM contracts. Whilst `GetSmartContractState()`
    may not fail if called on an address containing EVM code, it will
    not return meaningful results.


# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetSmartContractState",
    "params": ["fe001824823b12b58708bf24edd94d8b5e1cfcf7"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const smartContractState = await zilliqa.blockchain.getSmartContractState(
  "fe001824823b12b58708bf24edd94d8b5e1cfcf7"
);
console.log(smartContractState.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        String smartContractState = client.getSmartContractState("fe001824823b12b58708bf24edd94d8b5e1cfcf7");
        System.out.println(smartContractState);
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetSmartContractState("fe001824823b12b58708bf24edd94d8b5e1cfcf7"))
```

# Go

```go
func GetSmartContractState() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetSmartContractState("fe001824823b12b58708bf24edd94d8b5e1cfcf7")
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

!!! note

    The format of response has been changed\_

```json
{
  "_balance": "0",
  "admins": {
    "0xdfa89866ae86632b36361d53b76c1373448c28fa": {
      "argtypes": [],
      "arguments": [],
      "constructor": "True"
    }
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                                                                                                                                                                       |
| --------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                                                                                                                                                             |
| `jsonrpc` | string | Required | `"2.0"`                                                                                                                                                                                           |
| `method`  | string | Required | `"GetSmartContractState"`                                                                                                                                                                         |
| `params`  | string | Required | A smart contract address of 20 bytes. Example: `"fe001824823b12b58708bf24edd94d8b5e1cfcf7"` <br/><br/> Also supports Bech32 address <br/> Example: `"zil1lcqpsfyz8vfttpcghujwmk2d3d0pel8h3qptyu"` |
