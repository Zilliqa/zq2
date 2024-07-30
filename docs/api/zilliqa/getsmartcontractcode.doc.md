# Title

GetSmartContractCode

# Keywords

contract,smart contract,code,get,address

# Description

Returns the Scilla or EVM code associated with a smart contract address. Scilla code is represented as a `String` for the code, EVM code is returned as a hex representation of the compiled bytes. 

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetSmartContractCode",
    "params": ["fe001824823b12b58708bf24edd94d8b5e1cfcf7"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const smartContractCode = await zilliqa.blockchain.getSmartContractCode(
  "fe001824823b12b58708bf24edd94d8b5e1cfcf7"
);
console.log(smartContractCode.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<HttpProvider.ContractResult> smartContractCode = client.getSmartContractCode("fe001824823b12b58708bf24edd94d8b5e1cfcf7");
        System.out.println(new Gson().toJson(smartContractCode));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetSmartContractCode("fe001824823b12b58708bf24edd94d8b5e1cfcf7"))
```

# Go

```go
func GetSmartContractCode() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetSmartContractCode("fe001824823b12b58708bf24edd94d8b5e1cfcf7")
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
    "code": "scilla_version 0\n\n    (* HelloWorld contract *)\n    \n    import ListUtils\n    \n    (***************************************************)\n    (*               Associated library                *)\n    (***************************************************)\n    library HelloWorld\n    \n    let one_msg = \n      fun (msg : Message) => \n      let nil_msg = Nil {Message} in\n      Cons {Message} msg nil_msg\n    \n    let not_owner_code = Int32 1\n    let set_hello_code = Int32 2\n    \n    (***************************************************)\n    (*             The contract definition             *)\n    (***************************************************)\n    \n    contract HelloWorld\n    (owner: ByStr20)\n    \n    field welcome_msg : `String` = \"\"\n    \n    transition setHello (msg : `String`)\n      is_owner = builtin eq owner _sender;\n      match is_owner with\n      | False =>\n        msg = {_tag : \"Main\"; _recipient : _sender; _amount : Uint128 0; code : not_owner_code};\n        msgs = one_msg msg;\n        send msgs\n      | True =>\n        welcome_msg := msg;\n        msg = {_tag : \"Main\"; _recipient : _sender; _amount : Uint128 0; code : set_hello_code};\n        msgs = one_msg msg;\n        send msgs\n      end\n    end\n    \n    \n    transition getHello ()\n        r <- welcome_msg;\n        e = {_eventname: \"getHello()\"; msg: r};\n        event e\n    end",
    "language": "scilla"
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                                                                                                                                                                             |
| --------- | ------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                                                                                                                                                                   |
| `jsonrpc` | string | Required | `"2.0"`                                                                                                                                                                                                 |
| `method`  | string | Required | `"GetSmartContractCode"`                                                                                                                                                                                |
| `params`  | string | Required | A smart contract address of 20 bytes. <br/> Example: `"fe001824823b12b58708bf24edd94d8b5e1cfcf7"` <br/><br/> Also supports Bech32 address <br/> Example: `"zil1lcqpsfyz8vfttpcghujwmk2d3d0pel8h3qptyu"` |
