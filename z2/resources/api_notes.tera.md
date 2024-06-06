---
id: {{ id }}
title: API notes
keywords: api
---
---

# The Zilliqa 2 API

Zilliqa 2 provides a number of JSON-RPC APIs. 

In common with other blockchains, every node has global knowledge of
all transactions up to the last block it has seen, but not necessarily
knowledge of pending transactions. If you are dealing in pending
transactions (eg. to discover account nonces), you will need to
contact the same node for each call you wish to be consistent.

Individual nodes are strongly consistent.

A number of APIs are supported:

## `ots_`

ots_


