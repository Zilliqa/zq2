# zq2 block fetching

Zilliqa 2 nodes will, in general, start from either genesis or a checkpoint.

These will both be behind the current head of the blockchain, and the
node will thus want to catch up. To do so, it will attempt to request
blocks from other nodes.

This operation is complicated because:

 - Other nodes in the network may not be reliable - fail to reply,
   lie, or attempt to stop the node syncing.
 - Other nodes will, in general, not have all the blocks themselves -
   they may be syncing, or have pruned some blocks for resource
   management reasons.
 - We want to avoid overloading a single node with too much work.
 - The syncing node wants to catch up quickly.

As a result, the code for fetching blocks to complete our view of the
chain is somewhat complex. It consists of:

For essentially historical reasons, blocks are fetched by view, not block number.

## A range map implementation

In `range_map.rs`; this is a simple representation of a ranged set. I
did look for crates which did this, but found none which were
moderately simple and recently maintained.

## A block store

The block store is implemented in `block_store.rs`. It contains:

 * A buffered block cache.
 * The highest confirmed view (the view at the head of the chain) and
   the highest known view (the most recent view any node has alleged
   exists)
 * Some configuration parameters
 * This node's available blocks - those it has stored for transmission
   to other nodes - and the last time this was updated.
 * A list of `unserviceable_request` - requests this block wanted to
   send, but couldn't because no other node advertised that they had
   them available.

## A buffered block cache

This stores:

 * A cache of the oldest proposal sent to it (`cache`)
 * A cache of the newest propossals sent to it (`tail`)
 * A list of gaps in proposals sent to it (`empty_view_ranges`)
 * An index of parent hash -> block.

When a proposal comes in, it is sorted in to `cache` and `tail` -
`tail` exists so that we don't end up in a mess when we are nearly
synced, constantly asking for blocks near the head only to find that,
by the time we have recieved them, the head has moved on. It should
really be called `head`.

On a tick, `trim()` is called, which trims the cache contents back by
discarding the end of `cache` (the most recent blocks received - these
are the ones we're least likely to add to our growing head of chain
soon) and the beginning of `tail` (these are the ones that are least
likely to be recent soon).

We also discard any view ranges or blocks that are behind the head of
our canonical chain (we'll never need them).


## A tick hook

This is in `node_launcher.rs`, and calls `consensus.rs` periodically to:

 - Send any requests it feels it needs to complete the chain.
 - Prune the buffered block cache (see later)
 - Repeatedly pull the next block in the chain (by hash), check its
   integrity, and add it to the node's current view of the canonical
   chain if it checks out.

## A block store

This is held in `block_store.rs`

The fundamental ops are

### `request_missing_blocks()`

Which

 - Looks through the blocks we have
 - Finds the next blocks it thinks we need
 - Iterates through our known peers.

If we don't have availability for a peer, we will request it by
sending an empty block request.

If we do, we will try to request whatever blocks it has that we want.

We limit the number of outstanding requests per peer, in order to
avoid bufferbloat at the peer's input message queue.

We don't ask for blocks that we think are in flight (ie. we've
requested them but they have not yet arrived), those we don't think a
peer has, or those we think are gaps (remember that requests are made
by view, so you can't guarantee that every view has a block).

We time out outstanding requests on a flat-timeout basis (our model
being that if you haven't replied by now, the whole message has
probably been lost).

### `process_block()`

Which, called originally from `tick()`, given a block, will attempt to
process it. If it succeeded, it will try to retrieve the next block
from the cache and send a `ProcessProposal` message to process it.

We do this to avoid blocking `tick()` for too long.

## Block arrival

When blocks arrive (via `node.rs`'s `BlockResponse` handler), we put
them directly in the block store's buffer cache. The tick will then
process them next time it runs.

When new proposals arrive (from us via `process_block()`) via the
`ProcessProposal` message, we will attempt to process them. If this
results in a next proposal to process from the block buffer cache, we
will send another `ProcessProposal` message to process that one too.

## Forks

Forks are problematic. In particular, they break the flow of
parent-child hashes, so we have to go hunting for blocks in our buffer
which have parent hashes which our database knows about - we do this
using a progressive additive range search to avoid penalising our
database too much (see `fork_counter` in `block_store.rs`).

We may also never pick up a fork. Suppose the chain forked at view
202, giving a left hand block at 202 and a right hand block at 204
which then became the rest of the chain.

Now suppose we get 204, but never 202. How would we ever know that 202
existed? Well, we might not and will thus never store it in our
database. Be aware of this.

Also, the maximum depth of a fork is the maximum lookahead of our
cache. Suppose we have a fork 100 deep starting at view 202. We'll
fetch it, go to the end, and stop.

How would we ever know that there was another block whose parent was
the block at view 200? Well, unless we ask for subsequent blocks, we
won't. And we won't ask for subsequent blocks because we're too busy
re-requesting the ones we can't process.

This is theoretically fixable and we should one day - but I've not
done it today because long forks in Zilliqa 2 are not envisioned and
it would be hard both to write and to test.


