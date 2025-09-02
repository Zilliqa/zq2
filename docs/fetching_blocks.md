# ZQ2 block fetching

Zilliqa 2 nodes will, in general, start from either genesis or a checkpoint.

These will both be behind the current head of the blockchain, and the node will thus want to catch up. To do so, it will attempt to request blocks from other nodes.

This operation is complicated because:

- Other nodes in the network may not be reliable - fail to reply, lie, or attempt to stop the node syncing.
- Other nodes will, in general, not have all the blocks themselves - they may be syncing, or have pruned some blocks for resource management reasons.
- We want to avoid overloading a single node with too much work.
- The syncing node wants to catch up quickly.

As a result, the code for fetching blocks to complete our view of the chain is somewhat complex.

# Active Sync

Active-sync is the process of catching up to the head of the blockchain.
This process is designed to be aggressive i.e. it tries to catch up to the head as fast as possible.

This process consists of 3 main phases:
- Phase 1, downloading headers;
- Phase 2, downloading blocks; and
- Phase 3, finishing up.

## Phase 1

During this phase, the node will download headers, from segments of the chain, in descending order from the latest block seen. This way, it only downloads valid headers by simply following the chain of parent hashes.

Since this phase is I/O bound, the node fires multiple concurrent requests for different segments, to multiple peers. If it encounters any networking issues, it will resend the request for that segment to a subsequent peer. It checks and discards responses that are not linked by the chain of hashes and requests the same segment from a subsequent peer.

It does this until it downloads headers that link up to its own internal history, checkpoint, or genesis.

A node may enter this phase under two conditions:
- Sync from probe; or
- Sync from proposal.

### Sync Form Proposal

During normal operations, a node will check each block proposal received and it will start syncing if the block has a parent that does not exist in its own history.

This is the normal form of sync, triggered whenever a node falls *out of sync* with the rest of the network, for whatever reason.

### Sync From Probe

At startup, a node will probe its neighbouring peers for their best block and it will start syncing if the block is higher than what it has in its own history.

This is mainly used for nodes whose network may have stalled. Otherwise, it should be able to sync from proposal.

## Phase 2

During this phase, the node will download blocks in ascending order starting from the block that it has in its history. It sends the request to the same peer that provided the response in Phase 1.

Since this phase is CPU bound, the node requests one segment of the chain at a time. In order to avoid overflowing memory, it buffers only about 1,000 blocks at a time. If it encounters any networking issues, it will discard the response and repeat Phase 1 with the troublesome segment.

It does this until it has successfully downloaded all the blocks that it is aware of. This will bring it close to the head of the chain.

## Phase 3

Phase 1 and 2 may be repeated multiple times, which will bring the node close to the head of the chain but never quite reaching it. While Phase 1 and 2 are running, the node is also buffering the latest Proposals that it receives.

If the blocks that it has buffered, link up to its history, it will inject those blocks from its internal buffer. This will allow it to catch up to the head of the chain.

# Passive Sync

Passive-sync is the process of filling out the rest of the chain. This process is designed to be non-aggressive as it happens in the background.

A node that is started from a checkpoint, will run active-sync to catch up to the head. Then, it may run passive-sync to fill out the rest of the chain history going backwards.

This process consists of 1 main phase:
- Phase 4, downloading blocks;

## Phase 4

During this phase, a node determines the lowest block it has and requests for blocks down to *base_height* only.
Upon receiving a response from another node, it will store the blocks *ad-verbatim* without executing them.
The blocks can be executed later using the *State Sync* process below.

A node enters this phase only during normal operations, when it encounters a block Proposal that is successfully handled normally.
To enable this feature, set the `node.sync.base_height` to a value that is lower than the height of the existing block range.

# State Sync

State sync is the process of filling out the state history from an older checkpoint.
It is designed to import the state from the older checkpoint, and replay blocks going forwards from that checkpoint to the latest.

However, it requires that the node must already be in posession of the blocks stored in the checkpoint used (both the checkpoint block itself and its parent block).
This implies that the node must have completed both *Active Sync* and *Passive Sync* prior to this; and has synced beyond the checkpoint height.

To use this feature:
1. Start the node with `node.load_checkpoint` configured to the first checkpoint e.g. `013737600.dat`. Allow the node to active-sync up to the latest block.
2. Restart the node with the `node.sync.base_height` set below the height of the second checkpoint e.g. `13651100`. Allow the node to passive-sync down to the base height.
3. Restart the node with the `node.load_checkpoint` configured to the second checkpoint e.g. `013651200.dat`. Allow state-sync replay the blocks between the two checkpoints.

Note: This feature may take a while to run and the node is unable to participate in consensus during this time.
