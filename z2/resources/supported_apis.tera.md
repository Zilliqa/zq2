---
id: {{ _id }}
title: Supported APIs
keywords: api,support,level,documented,implemented
---
---
# Supported APIs

## Consistency

Zilliqa 2, in common with other blockchains, has a strict consistency model for individual nodes and historical transactions, but eventual consistency for pending transactions and the network as a whole.

 * Once a node has seen a transaction - pending or finalised - it will always be present at that node.
 * Nodes can be assumed to have knowledge of all transactions at or before their last seen finalised block.
 * Different nodes will have different last seen finalized blocks (though at least 2/3 of nodes will have seen the latest finalised block at any consensus round)
 * Pending transactions flow through the network and may never be seen at all nodes (they may not reach a node before they are included in a block).

This means that if you want to rely on the properties of pending transactions (eg. for monitoring the account nonce), you will need to communicate with a single node.

## Supported APIs

Zilliqa 2 supports APIs from a number of sources:

 * `erigon_` and `ots_` APIs are provided for compatibility with
   Zilliqa's fork of
   [otterscan](https://github.com/Zilliqa/otterscan). These APIs are
   intended to be compatible with [the otterscan json-rpc API
   spec](https://github.com/otterscan/otterscan/blob/develop/docs/custom-jsonrpc.md).

 * Ethereum APIs (generally prefixes with `eth_`) are intended to be compatible with Zilliqa 1, [geth](https://geth.ethereum.org/) and [erigon](https://erigon.tech/). 
   Some reference material is also taken from the [Ethereum JSON-RPC spec](https://ethereum.github.io/execution-apis/api-documentation/),  [quicknode](https://www.quicknode.com/docs/ethereum), [infura](docs.infura.io) and [alchemy](https://docs.alchemy.com/reference).

  * Zilliqa APIs are intended, as far as possible, to be compatible with existing Zilliqa 1 applications. There are various differences due to the different construction of Zilliqa 2 which are noted on the individual API pages.

## Unsupported APIs

Zilliqa 2 does not support the ethereum node to node protocol. You cannot sync transactions between Zilliqa 2 and Ethereum nodes.

## Differences from other ethereum implementations

 * D0001: Zilliqa (and Zilliqa 2) will, in general, ignore extra arguments to JSON-RPC calls where other EVM implementations will raise an error.

## Common definitions for eth_ API calls

## List of entry points

If an API is not mentioned in this table, support for it is not planned.
Please open an issue or PR for APIs that you think should be included.

🟢 = Fully supported

🟠 = Partially implemented, full support planned

🔴 = Not yet implemented, full support planned

🔵 = Inapplicable to Zilliqa 2; we have no plans to implement it.

🟣 = Implemented, but not yet documented.



| Method                                    | Status                                          |
| ----------------------------------------- | ----------------------------------------------- |
{% for api in apis -%}
| {%- if api.method.JsonRpc -%}
`{{ api.method.JsonRpc.name }}`
{%- endif -%}
{%- if api.method.Rest -%}
{{ `api.method.Rest.uri` }}
{%- endif -%}                               | {% if api.status == "Implemented" %}🟢
{%- elif api.status == "NotYetImplemented" -%}🔴
{%- elif api.status == "PartiallyImplemented" -%}🟠
{%- elif api.status == "NeverImplemented" -%}🔵
{%- elif api.status == "NotYetDocumented" -%}🟣
{%- endif -%}           |
{% endfor %}

