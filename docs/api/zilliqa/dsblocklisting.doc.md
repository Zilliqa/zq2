# Title

DSBlockListing

# Keywords

ds,block,listing

# Description

Returns a paginated list of up to **10** Directory Service (DS) blocks and their
block hashes for a specified page. The `maxPages` variable that specifies the
maximum number of pages available is also returned.
Deprecated in ZQ2; now returns a constant placeholder value.

# Curl

```shell
    curl -d '{
        "id": "1",
        "jsonrpc": "2.0",
        "method": "DSBlockListing",
        "params": [1]
    }' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Nodejs

```js
    const dsBlockListing = await zilliqa.blockchain.getDSBlockListing(1);
    console.log(dsBlockListing.result);
```

# Java

```java
    public class App {
        public static void main(String[] args) throws IOException {
            HttpProvider client = new HttpProvider("{{ _api_url }}");
            Rep<BlockList> blockListing = client.getDSBlockListing(1);
            System.out.println(new Gson().toJson(blockListing));
        }
    }
```

# Python

```python
    from pyzil.zilliqa import chain
    chain.set_active_chain(chain.MainNet)
    print(chain.active_chain.api.DSBlockListing(1))
```

# Go

```go
    func DSBlockListing() {
    provider := NewProvider("{{ _api_url }}")
    response := provider.DSBlockListing(1)
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
        "BlockNum": 5898,
        "Hash": "4DEED80AFDCC89D5B691DCB54CCB846AD9D823D448A56ACAC4DBE5E1213244C7"
      },
      {
        "BlockNum": 5897,
        "Hash": "968E2E7820A3795DE8C8A7A2E94379CC10F50ADA5EA6F90C03C4E61E22EE83B5"
      },
      {
        "BlockNum": 5896,
        "Hash": "A52D113357910ADECEFA713D89A667030F521FFB153EEFA97A0D9E7E4AA5230B"
      },
      {
        "BlockNum": 5895,
        "Hash": "8d49d4b18b441dc0da6ca580f468c9e83278c47f0f54fe342e1fe1425c39044f"
      },
      {
        "BlockNum": 5894,
        "Hash": "b966c36557480a35a36a0d1c33723fd9bac8538588dea6716b4dfb2a05815458"
      },
      {
        "BlockNum": 5893,
        "Hash": "fc20118eec0f14fdc089fcfee528276337dcf403a308153485f24f2856998613"
      },
      {
        "BlockNum": 5892,
        "Hash": "4ed593d66b1ea5fa9a77cc1bb119baf90029c249bf5507b01079bc2fbf45aec7"
      },
      {
        "BlockNum": 5891,
        "Hash": "1385bf48e584ebb82cf11a9064d99b5e0b4ae560866a92efe9b78604e08fc821"
      },
      {
        "BlockNum": 5890,
        "Hash": "05d6d24a8f5411ff70fe58a09f38fd4b49ec4122b7c26817964a4a8b8a089c1f"
      },
      {
        "BlockNum": 5889,
        "Hash": "137e56be8966eba0c04138d79faa1515997fc790ccf5213c00bb13a3550cca39"
      }
    ],
    "maxPages": 590
  }
}
```

# Arguments

| Parameter | Type   | Required | Description                                                |
| --------- | ------ | -------- | ---------------------------------------------------------- |
| `id`      | string | Required | `"1"`                                                      |
| `jsonrpc` | string | Required | `"2.0"`                                                    |
| `method`  | string | Required | `"DSBlockListing"`                                         |
| `params`  | number | Required | Specifed page of DS blocks listing to return. Example: `1` |
