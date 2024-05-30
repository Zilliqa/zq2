# Title

TxBlockListing

# Keywords

tx,block,listing

# Description

Returns a paginated list of up to **10** Transaction blocks and their block hashes for a specified page. The `maxPages` variable that specifies the maximum number of pages available is also returned.

# Curl

```shell
curl -d '{
    "id": "1",
    "jsonrpc": "2.0",
    "method": "TxBlockListing",
    "params": [1]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# NodeJs

```js
const txBlockListing = await zilliqa.blockchain.getTxBlockListing(1);
console.log(txBlockListing.result);
```

# Java

```java
public class App {
    public static void main(String[] args) throws IOException {
        HttpProvider client = new HttpProvider("{{ _api_url }}");
        Rep<BlockList> blockListing = client.getTxBlockListing(1);
        System.out.println(new Gson().toJson(blockListing));
    }
}
```

# Python

```python
from pyzil.zilliqa import chain
chain.set_active_chain(chain.MainNet)
print(chain.active_chain.api.GetTxBlockListing(1))
```

# Go

```go
func TxBlockListing() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.TxBlockListing(1)
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
    "data": [
      {
        "BlockNum": 589790,
        "Hash": "E0743F8E0CAEFB4DD6B15D9A5B71975CD1CFFC453EC57F85541E224A9C60B4E8"
      },
      {
        "BlockNum": 589789,
        "Hash": "01a61cc22ab5ae1d77cd6da65385771dca408fbea90688c845bdd2ffe1797bb7"
      },
      {
        "BlockNum": 589788,
        "Hash": "be825dd949caf36d6a20372fdc88b1912dc1515d1ecf8624e6cd928b33c9a705"
      },
      {
        "BlockNum": 589787,
        "Hash": "4d097b9e283dd2bfeb78f2bb6ef9fe960b45b96e027f999316cea4c3d8f70ea9"
      },
      {
        "BlockNum": 589786,
        "Hash": "1714472999972237b887db32cc6e27c44dc4ceecdc310ae3b18f44673e860d87"
      },
      {
        "BlockNum": 589785,
        "Hash": "a40cb278801b22609245e240c1386894829d36ec2c081cf33d6b0f11cb6d6c70"
      },
      {
        "BlockNum": 589784,
        "Hash": "e6a66682866dec2b44124b0daa419696cca396bc04ab2d342a65b43db5cbd24e"
      },
      {
        "BlockNum": 589783,
        "Hash": "a7be65da85167c2cd0b044698a3e7dc74e2478b367f87d85536d4c108d9fde96"
      },
      {
        "BlockNum": 589782,
        "Hash": "060b06d40fcca1cedb9099031e1cb37927700bc263f14a3b05481f1f9b211b7c"
      },
      {
        "BlockNum": 589781,
        "Hash": "db190feb1f2099875ca2dc9734efbeb5b1cef676f85d7fa9a4b84d64a9e463b6"
      }
    ],
    "maxPages": 58980
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                                |
| --------- | ------ | -------- | ---------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                      |
| `jsonrpc` | string | Required | `"2.0"`                                                    |
| `method`  | string | Required | `"TxBlockListing"`                                         |
| `params`  | number | Required | Specifed page of TX blocks listing to return. Example: `1` |
