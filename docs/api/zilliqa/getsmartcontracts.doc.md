# Title

GetSmartContracts

# Keywords

contract,get,list

# Description

Returns the list of smart contract addresses created by an User's account.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetSmartContracts",
    "params": ["1eefc4f453539e5ee732b49eb4792b268c2f3908"]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const smartContracts = await zilliqa.blockchain.getSmartContracts(
  "1eefc4f453539e5ee732b49eb4792b268c2f3908"
);
console.log(smartContracts.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<List<Contract>> smartContracts = client.getSmartContracts("fe001824823b12b58708bf24edd94d8b5e1cfcf7");
        System.out.println(new Gson().toJson(smartContracts));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetSmartContracts("fe001824823b12b58708bf24edd94d8b5e1cfcf7"))
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": [
    {
      "address": "6b3070b0abf4371b2b3b26e23f11f4c073b636e5"
    },
    {
      "address": "13cf0f8c1ea003779df0b7fa08a97903bc760e80"
    }
  ]
}
```

# Arguments

| Parameter | Type   | Required | Description                                                                                                                                                                                              |
| --------- | ------ | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                                                                                                                                                                    |
| `jsonrpc` | string | Required | `"2.0"`                                                                                                                                                                                                  |
| `method`  | string | Required | `"GetSmartContracts"`                                                                                                                                                                                    |
| `params`  | string | Required | An User's account address of 20 bytes. <br/> Example: `"1eefc4f453539e5ee732b49eb4792b268c2f3908"` <br/><br/> Also supports Bech32 address <br/> Example: `"zil1rmhufazn2w09aeejkj0tg7fty6xz7wggup2tsh"` |


