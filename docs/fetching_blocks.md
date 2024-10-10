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

Blocks are fetched by view, not block number; it's important to keep
these distinct - there may be many blocks with block number 5, but
only one view.

## A range map implementation

In `range_map.rs`; this is a simple representation of a ranged set. I
did look for crates which did this, but found none which were
moderately simple and recently maintained.

## A block store

The block store is implemented in `block_store.rs` - see that file for
details; the block store is responsible for providing access to the
blocks requested by the rest of the system.

To do so, it contains mechanisms to request blocks and to cache blocks
which it may one day be able to prove are part of the canonical chain.

## A tick hook

This is in `node_launcher.rs`, and calls `consensus.rs` periodically to
drive the block fetching state machine.

## A block store

This is held in `block_store.rs`

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

