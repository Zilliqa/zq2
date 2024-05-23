# Title

GetNetworkId

# Keywords

network,id,get

# Description

Returns the `CHAIN_ID` of the specified network. This is represented as a `String`.

Our chain ids are listed at [chainlist.org](https://chainlist.org/?search=zilliqa&testnets=true).

The chain id reported by the Zilliqa API has bit 15 clear (`chain_id & ~0x8000`) whilst the chain id reported by the EVM API has bit 15 set (`chain_id | 0x8000`).

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetNetworkId",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const NetworkId = await zilliqa.network.GetNetworkId();
console.log(NetworkId);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> networkId = client.getNetworkId();
        System.out.println(new Gson().toJson(networkId));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
from pyzil.zilliqa.api import ZilliqaAPI

# EITHER
chain.set_active_chain(chain.MainNet)
network_id = chain.active_chain.api.GetNetworkId()
print(network_id)

# OR
new_api = ZilliqaAPI(endpoint="{{ _api_url }}")
network_id = new_api.GetNetworkId()
print(network_id)
```

# Go

```go
func GetNetworkId() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetNetworkId()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
 }
 ```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "1"
}
```

# Arguments

| Parameter | Type   | Required | Description       |
| --------- | ------ | -------- | ----------------- |
| `id`      | string | Required | `"1"`             |
| `jsonrpc` | string | Required | `"2.0"`           |
| `method`  | string | Required | `"GetNetworkId"`  |
| `params`  | string | Required | Empty string `""` 
|
