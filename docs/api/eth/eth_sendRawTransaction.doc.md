# Title

eth_sendRawTransaction

# Keywords

eth,transaction,send,raw

# Description

Sends a raw, RLP-encoded transaction to the blockchain. The response contains the hash of the transaction, or an RPC error if the transaction data was invalid.

# Curl

```sh
curl -d '{ 
    "id": 2,
    "jsonrpc": "2.0",
    "method": "eth_sendRawTransaction",
    "params": [
        "0xf86c01860454b7a4e10082f7fd9445c3e57617b87c0e24d66b3eb4860a87bfeef25a8084011afdd78301059ca05095144e5761cdd26ebd05f76f4cc5dec9a3d837181b5c1796582d1227761ac7a05b2cbf78c2b8db98141fbb0cdf967b4b3e3ed5edf53de79c88480a0d6dd94cf0"
    ]
}' -H "Content-Type: application/json" -X POST "{{ _api_url }}"
```

# Response

```sh
{
    "id": 2,
    "jsonrpc": "2.0",
    "result": "0xa5b9dbb7198ef43095ad62327df5ddfb92846c6f55ee85ef716b87bee1561363"
}
```

# Arguments

| Parameter | Type   | Required | Description                |
|-----------|--------|----------|----------------------------|
| `id`      | string | Required | `"1"`                      |
| `jsonrpc` | string | Required | `"2.0"`                    |
| `method`  | string | Required | `"eth_sendRawTransaction"` |
| `params`  | array  | Requred  | `[ data ]`           |
