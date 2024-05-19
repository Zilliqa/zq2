# Title

GetTotalCoinSupply

# Keywords

get,coin,total,supply

# Description

`GetTotalCoinSupply` Returns the total supply (ZIL) of coins in the network. This is represented as a
`String`.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetTotalCoinSupply",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const totalCoinSupply = await zilliqa.blockchain.getTotalCoinSupply();
console.log(totalCoinSupply);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> totalCoinSupply = client.getTotalCoinSupply();
        System.out.println(new Gson().toJson(totalCoinSupply));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
from pyzil.zilliqa.api import ZilliqaAPI

# EITHER
chain.set_active_chain(chain.MainNet)
total_coin_supply = chain.active_chain.api.GetTotalCoinSupply()
print(total_coin_supply)

# OR
new_api = ZilliqaAPI(endpoint="{{_api_url}}")
total_coin_supply = new_api.GetTotalCoinSupply()
print(total_coin_supply)
```

# Go

```go
func GetTotalCoinSupply() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetTotalCoinSupply()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response


```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "13452081092.277490607172"
}
```

# Arguments


| Parameter | Type   | Required | Description                                       |
| --------- | ------ | -------- | ------------------------------------------------- |
| `id`      | string | Required | `"1"`                                             |
| `jsonrpc` | string | Required | `"2.0"`                                           |
| `method`  | string | Required | `"GetTotalCoinSupply or GetTotalCoinSupplyAsInt"` |
| `params`  | string | Required | Empty string `""`                                 |
