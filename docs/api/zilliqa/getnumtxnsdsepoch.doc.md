# Title

GetNumTxnsDSEpoch

# Keywords

get,count,transactions,ds,epoch

# Description

Returns the number of validated transactions included in this DS epoch. This is represented as a `String`.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "GetNumTxnsDSEpoch",
    "params": [""]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const numTxnsDSEpoch = await zilliqa.blockchain.getNumTxnsDSEpoch();
console.log(numTxnsDSEpoch.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<String> numTxnsDSEpoch = client.getNumTxnsDSEpoch();
        System.out.println(new Gson().toJson(numTxnsDSEpoch));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetNumTxnsDSEpoch())
```

# Go

```go
func GetNumTxnsDSEpoch() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.GetNumTxnsDSEpoch()
    result, _ := json.Marshal(response)
    fmt.Println(string(result))
}
```

# Response

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "result": "416"
}
```

# Arguments

| Parameter | Type   | Required | Description           |
| --------- | ------ | -------- | --------------------- |
| `id`      | string | Required | `"1"`                 |
| `jsonrpc` | string | Required | `"2.0"`               |
| `method`  | string | Required | `"GetNumTxnsDSEpoch"` |
| `params`  | string | Required | Empty string `""`     |
