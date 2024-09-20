# zq2 block fetching

Zilliqa 2 nodes will, in general, start from either genesis or a checkpoint.

These will both be behind the current head of the blockchain, and the node will thus want to catch up. To do so, it will attempt to request blocks from other nodes.

This operation is complicated because:

 - Other nodes in the network may not be reliable - fail to reply, lie, or attempt to stop the node syncing.
 - Other nodes will, in general, not have all the blocks themselves - they may be syncing, or have pruned some blocks for resource management reasons.
 - We want to avoid overloading a single node with too much work.
 - The syncing node wants to catch up quickly.

As a result, the code for fetching blocks to complete our view of the chain is somewhat complex. It consists of:

For essentially historical reasons, blocks are fetched by view, not block number.

## A range map implementation

In `range_map.rs`; this is a simple representation of a ranged set. I
did look for crates which did this, but found none which were
moderately simple and recently maintained.

## A block store

The block store is implemented in `block_store.rs`. It contains:

 * A buffered block cache.
 * The highest confirmed view (the view at the head of the chain) and the highest known view (the most recent view any node has alleged exists)
 * Some configuration parameters
 * This node's available blocks - those it has stored for transmission to other nodes - and the last time this was updated.
 * A list of `unserviceable_request` - requests this block wanted to send, but couldn't because no other node advertised that they had them available.

## A buffered block cache

This stores:

 * 

## A tick hook

This is in `node_launcher.rs`, and calls `consensus.rs` periodically to:

 - Send any requests it feels it needs to complete the chain.
 - Prune the buffered block cache (see later)
 - Repeatedly pull the next block in the chain (by hash), check its
   integrity, and add it to the node's current view of the canonical
   chain if it checks out.

## A block fetcher

This is held in `block_store.rs`
   
The fundamental tool used to 
