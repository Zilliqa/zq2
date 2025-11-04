# RPC Rate Limit

Version `v0.20.0` comes with an RPC rate-limit feature.
The purpose of this feature is to manage/mitigate abuse of the RPC API.

It has a fairly basic credit-limit mechanism:
1. Each caller is assigned a quota of credits within a time period.
2. Each RPC method has a certain credit-rate assigned to it.
3. The caller's quota balance is decremented by the credit rate of the RPC method, when the call is made.
4. If the caller's balance hits zero, any subsequent calls will be rejected with an error response.

The error response is a standard JSON-RPC response with the following structure:

```json
{"jsonrpc":"2.0","id":"0","error":{"code":-32000,"message":"RPC_RATE_LIMIT"}}
```

## Redis Server

The credit-store uses Redis as the state storage.
The `REDIS_ENDPOINT` environment string is used to specify the Redis server connection details e.g. `redis://user:pass@localhost:6379`.
If no Redis server is available or specified, the feature is disabled.

## Default Policy
The default policy is to `Allow` all RPC calls.

In case the Redis server is unavailable during node startup, the feature is disabled entirely.
In case the Redis server becomes unavailable during operation, the call is allowed regardless of balance.


## Credit Rates
The credit rate for each RPC method can be defined in the `nodes.credit_rates` section of the configuration file.
This allows the rates to be easily changed without modifying the code.
A sample credit rate is provided in the `z2/resources/rpc_rates.toml` file.

Example:
```toml
[credit_rates]
eth_estimateGas = 300
eth_getBlockReceipts = 1000
eth_getBlockTransactionCountByNumber = 150
eth_sendRawTransaction = 80
eth_syncing = 5
```

The pricing may be derived from empirical estimates of the typical time it takes to service a request.
The arbitrary conversion rate used is `1 credit/ms`.
The credit rate for any unspecified RPC method, defaults to 500.

## Default Quota
Since each API server listens on a separate port, and provides a different set of RPC methods, the credit limits can be customized for each server, separately.
It is defined as the following object under the `default_quota` section of each API server.

This allows limits to be customised, depending on service e.g. an externally facing port may have its credit limit reduced to prevent abuse; while an internal facing port may have its credit limit increased to allow for more requests.

The `default_quota` object has two fields:
- `balance`: The amount of credits assigned at each time period.
- `period`: The time period (in seconds) for which the balance is available.

Example:
```toml
default_credit = { balance = 10000, period = 60 }
```
In the example above, the default rate limit is set to 10000 credits per 60 seconds.
If unspecified, the default rate limit is, unlimited.
